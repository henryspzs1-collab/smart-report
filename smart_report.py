from flask import Flask, jsonify, request, Response, g
import json
import os
import socket
import re
import secrets
import string
import io
import zipfile
import hashlib
import base64
from datetime import datetime, timedelta
from urllib import request as urlreq
from urllib.error import HTTPError, URLError
import bcrypt

app = Flask(__name__)
# Limite de upload (fotos/PDF em base64): 60 MB
app.config['MAX_CONTENT_LENGTH'] = 60 * 1024 * 1024


@app.errorhandler(Exception)
def _handle_uncaught(e):
    """Nunca devolve HTML cru: erros viram JSON e o traceback vai pro log do Render."""
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return jsonify({"error": e.description, "code": e.code}), e.code
    import traceback
    import sys
    traceback.print_exc(file=sys.stdout)
    sys.stdout.flush()
    return jsonify({"error": f"Erro interno no servidor: {type(e).__name__}: {e}"}), 500


# -------- Auth helpers --------
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')


def verify_password(plain: str, hashed: str) -> bool:
    if not plain or not hashed:
        return False
    try:
        return bcrypt.checkpw(plain.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False


def generate_temp_password(length: int = 10) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


# -------- Sessões (tokens aleatórios) --------
SESSION_TTL_DAYS = 30


def _prune_sessions(sessions):
    cutoff = (datetime.utcnow() - timedelta(days=SESSION_TTL_DAYS)).isoformat() + "Z"
    for t in [t for t, s in sessions.items() if (s.get('createdAt') or '') < cutoff]:
        del sessions[t]


def _create_session(full_data, username):
    sessions = full_data.setdefault('sessions', {})
    _prune_sessions(sessions)
    token = secrets.token_urlsafe(32)
    sessions[token] = {"username": username, "createdAt": datetime.utcnow().isoformat() + "Z"}
    return token


def _resolve_token(full_data, token):
    """Token de sessão -> username. None se inválido/expirado."""
    if not token:
        return None
    s = (full_data.get('sessions') or {}).get(token)
    if not s:
        return None
    cutoff = (datetime.utcnow() - timedelta(days=SESSION_TTL_DAYS)).isoformat() + "Z"
    if (s.get('createdAt') or '') < cutoff:
        return None
    username = s.get('username')
    if username not in full_data.get('users', {}):
        return None
    return username


# -------- Rate limit simples de login (em memória) --------
_login_attempts = {}  # username -> [timestamps]


def _login_blocked(username):
    import time
    now = time.time()
    attempts = [t for t in _login_attempts.get(username, []) if now - t < 300]  # janela 5 min
    _login_attempts[username] = attempts
    return len(attempts) >= 8


def _login_record_fail(username):
    import time
    _login_attempts.setdefault(username, []).append(time.time())


EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_valid_email(email: str) -> bool:
    return bool(email and EMAIL_REGEX.match(email))


def public_user_view(username: str, user: dict) -> dict:
    """Retorna dados do usuário SEM o passwordHash."""
    return {
        "username": username,
        "role": user.get("role", "user"),
        "status": user.get("status", "active"),
        "firstName": user.get("firstName", ""),
        "lastName": user.get("lastName", ""),
        "email": user.get("email", ""),
        "phone": user.get("phone", ""),
        "mustResetPassword": user.get("mustResetPassword", False),
        "createdAt": user.get("createdAt", ""),
        "filialId": user.get("filialId", "matriz")
    }


def ensure_user_fields(user: dict) -> dict:
    """Garante que o dict de usuário tem todos os campos padrão."""
    defaults = {
        "role": "user",
        "status": "active",
        "firstName": "",
        "lastName": "",
        "email": "",
        "phone": "",
        "mustResetPassword": False,
        "createdAt": datetime.utcnow().isoformat() + "Z",
        "filialId": "matriz"
    }
    for k, v in defaults.items():
        if k not in user:
            user[k] = v
    return user

# Arquivo onde os dados serão salvos permanentemente no seu PC
# Em produção (Render), aponte para um disco persistente via variável de ambiente DATA_FILE
DATA_FILE = os.environ.get("DATA_FILE", "bateria_data.json")
BACKUP_DIR = os.path.join(os.path.dirname(DATA_FILE) or '.', 'backups')


def _backup_daily(data):
    """No máximo 1 backup por dia, mantém os 14 mais recentes. Best-effort."""
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        today = datetime.utcnow().strftime('%Y%m%d')
        path = os.path.join(BACKUP_DIR, f'bateria_data_{today}.json')
        if not os.path.exists(path):
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False)
            files = sorted(os.path.join(BACKUP_DIR, x) for x in os.listdir(BACKUP_DIR) if x.startswith('bateria_data_'))
            for old in files[:-14]:
                try:
                    os.remove(old)
                except Exception:
                    pass
    except Exception as e:
        import sys
        print(f"[BACKUP] falhou: {e}", flush=True)


def _latest_backup():
    try:
        files = sorted(os.path.join(BACKUP_DIR, x) for x in os.listdir(BACKUP_DIR) if x.startswith('bateria_data_'))
        return files[-1] if files else None
    except Exception:
        return None


# -------- Assets de laudo (fotos fora do JSON) --------
# As fotos dos laudos salvos vão pra arquivos; no JSON fica só uma referência "asset://...".
# O contrato externo (base64) é preservado: save externaliza, load/export reinflam.
ASSET_DIR = os.path.join(os.path.dirname(DATA_FILE) or '.', 'laudo_assets')


def _safe_name(s):
    return re.sub(r'[^a-zA-Z0-9_.-]', '_', str(s))[:80]


def _mime_ext(data_uri):
    head = data_uri[:50]
    if 'image/png' in head:
        return 'image/png', 'png'
    if 'image/webp' in head:
        return 'image/webp', 'webp'
    return 'image/jpeg', 'jpg'


def _externalize_images(user, lid, state):
    """Grava reportImages (base64) como arquivos e troca o src por 'asset://...'. Retorna cópia do state."""
    if not isinstance(state, dict) or not isinstance(state.get('reportImages'), list):
        return state
    try:
        os.makedirs(ASSET_DIR, exist_ok=True)
    except Exception:
        return state
    prefix = f"{_safe_name(user)}__{_safe_name(lid)}__"
    # Remove assets antigos deste laudo (evita órfãos ao re-salvar)
    try:
        for fn in os.listdir(ASSET_DIR):
            if fn.startswith(prefix):
                os.remove(os.path.join(ASSET_DIR, fn))
    except Exception:
        pass
    new_imgs = []
    for idx, img in enumerate(state['reportImages']):
        src = img.get('src') if isinstance(img, dict) else None
        if isinstance(src, str) and src.startswith('data:') and 'base64,' in src:
            mime, ext = _mime_ext(src)
            fn = f"{prefix}{idx}.{ext}"
            try:
                with open(os.path.join(ASSET_DIR, fn), 'wb') as f:
                    f.write(base64.b64decode(src.split('base64,', 1)[1]))
                img = {**img, "src": "asset://" + fn}
            except Exception:
                pass  # se falhar, mantém base64 (seguro)
        new_imgs.append(img)
    return {**state, "reportImages": new_imgs}


def _inflate_images(state):
    """Troca refs 'asset://...' de volta por data URI base64. Retorna cópia do state."""
    if not isinstance(state, dict) or not isinstance(state.get('reportImages'), list):
        return state
    new_imgs = []
    for img in state['reportImages']:
        src = img.get('src') if isinstance(img, dict) else None
        if isinstance(src, str) and src.startswith('asset://'):
            fn = src[len('asset://'):]
            mime = 'image/png' if fn.endswith('.png') else ('image/webp' if fn.endswith('.webp') else 'image/jpeg')
            try:
                with open(os.path.join(ASSET_DIR, fn), 'rb') as f:
                    b64 = base64.b64encode(f.read()).decode('ascii')
                img = {**img, "src": f"data:{mime};base64,{b64}"}
            except Exception:
                img = {**img, "src": ""}  # arquivo sumiu
        new_imgs.append(img)
    return {**state, "reportImages": new_imgs}


def _delete_laudo_assets(user, lid):
    prefix = f"{_safe_name(user)}__{_safe_name(lid)}__"
    try:
        for fn in os.listdir(ASSET_DIR):
            if fn.startswith(prefix):
                os.remove(os.path.join(ASSET_DIR, fn))
    except Exception:
        pass


def _inflate_laudos_map(laudos):
    """Reinfla as imagens de TODOS os laudos (pra export self-contained). Cópia, não muta."""
    out = {}
    for uname, ulaudos in (laudos or {}).items():
        out[uname] = {}
        for lid, laudo in (ulaudos or {}).items():
            if isinstance(laudo, dict) and 'state' in laudo:
                out[uname][lid] = {**laudo, "state": _inflate_images(laudo.get('state') or {})}
            else:
                out[uname][lid] = laudo
    return out

# Configuração padrão de perguntas
DEFAULT_QUESTIONS = [
    {"id": "1", "type": "checkbox", "label": "Conector danificado ou com sinal de aquecimento"},
    {"id": "2", "type": "checkbox_qty", "label": "Borrachas da tampa faltando", "subLabel": "Quantas?"},
    {"id": "3", "type": "checkbox_qty", "label": "Borrachas da tampa danificadas", "subLabel": "Quantas?"},
    {"id": "4", "type": "checkbox_qty", "label": "Borrachas da base danificadas", "subLabel": "Quantas?"},
    {"id": "5", "type": "checkbox_qty", "label": "Borrachas da base faltando", "subLabel": "Quantas?"},
    {"id": "6", "type": "checkbox_text", "label": "Bateria apresenta anomalia no funcionamento?",
     "subLabel": "Se sim, descreva o porquê"},
    {"id": "7", "type": "checkbox", "label": "Adesivo da tampa trincado ou danificado"},
]

# Configuração Padrão dos Campos de Informações Gerais
DEFAULT_HEADER_CONFIG = [
    {"id": "client", "label": "Nome do Cliente / Empresa", "type": "text"},
    {"id": "model", "label": "Variação / Especificação do Modelo", "type": "text"},
    {"id": "serial", "label": "Número de Série (S/N)", "type": "text"},
    {"id": "defect", "label": "Defeito Alegado pelo Cliente", "type": "textarea"}
]


def load_data():
    data = {}
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            import sys
            print(f"[LOAD_DATA] falha ao ler {DATA_FILE}: {e}", flush=True)
            # NUNCA recriar do zero por cima de dados existentes (apagaria tudo).
            # Tenta o backup mais recente; se não der, aborta.
            bkp = _latest_backup()
            if bkp:
                try:
                    with open(bkp, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    print(f"[LOAD_DATA] recuperado do backup {bkp}", flush=True)
                except Exception:
                    raise RuntimeError("Dados corrompidos e backup ilegível")
            else:
                raise RuntimeError("Dados corrompidos e sem backup disponível")

    # MUDANÇA DRÁSTICA: Migração automática para sistema Multiusuário
    if "globalConfig" not in data:
        # Pega as configurações base (ou o que já existia)
        header_config = data.get("headerConfig", DEFAULT_HEADER_CONFIG)
        legacy_questions = data.get("checklistConfig", DEFAULT_QUESTIONS)
        models = data.get("models", [{
            "id": "modelo_padrao_1",
            "name": "Bateria Padrão",
            "questions": legacy_questions,
            "diagrams": []
        }])

        # Pega o estado do laudo antigo e atribui ao admin para não perder nada
        header_data = data.get("headerData", {"date": "", "selectedTemplateId": models[0]["id"] if models else "",
                                              "showSignatures": True})

        _adm_pw = generate_temp_password(12)
        import sys
        print(f"[SETUP] Admin inicial criado -> usuario: admin | senha temporaria: {_adm_pw} (troque no primeiro acesso)", flush=True)
        data = {
            "users": {
                "admin": {
                    "passwordHash": hash_password(_adm_pw),
                    "role": "admin",
                    "status": "active",
                    "firstName": "Administrador",
                    "lastName": "",
                    "email": "",
                    "phone": "",
                    "mustResetPassword": True,
                    "createdAt": datetime.utcnow().isoformat() + "Z"
                }
            },
            "globalConfig": {
                "headerConfig": header_config,
                "models": models,
                "logo": data.get("logo", None)
            },
            "userStates": {
                "admin": {
                    "headerData": header_data,
                    "answers": data.get("answers", {}),
                    "diagramMarks": data.get("diagramMarks", {}),
                    "reportImages": data.get("reportImages", []),
                    "pdfMargin": data.get("pdfMargin", "1.5cm")
                }
            }
        }
        save_data(data)

    # Migração de usuários antigos (password em texto puro -> passwordHash)
    changed = False
    for uname, u in data.get("users", {}).items():
        if "password" in u and "passwordHash" not in u:
            u["passwordHash"] = hash_password(u["password"])
            del u["password"]
            changed = True
        before = dict(u)
        ensure_user_fields(u)
        if u != before:
            changed = True

    # Migração: filiais (multi-empresa Omie). "matriz" usa as credenciais das env vars.
    if "filiais" not in data:
        data["filiais"] = {
            "matriz": {
                "id": "matriz",
                "nome": "Matriz",
                "omieAppKey": "",      # vazio = usa OMIE_APP_KEY do ambiente
                "omieAppSecret": ""
            }
        }
        changed = True
    # Garante que todo usuário tem filialId (default: matriz)
    for uname, u in data.get("users", {}).items():
        if "filialId" not in u:
            u["filialId"] = "matriz"
            changed = True

    # Segurança: desativa o admin padrão se ainda estiver com a senha "admin" (uma vez só).
    if not data.get("_adminDefaultChecked"):
        adm = data.get("users", {}).get("admin")
        if adm and adm.get("status") == "active" and verify_password("admin", adm.get("passwordHash", "")):
            adm["status"] = "disabled"
            import sys
            print("[SETUP] Admin padrão (admin/admin) DESATIVADO por segurança.", flush=True)
        data["_adminDefaultChecked"] = True
        changed = True

    if changed:
        save_data(data)

    return data


def save_data(data):
    # Gravação atômica: escreve num temp e troca (os.replace). Assim um leitor nunca
    # pega o arquivo pela metade (que causava lista vazia intermitente).
    tmp = DATA_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, DATA_FILE)
    _backup_daily(data)


@app.route('/api/login', methods=['POST'])
def login():
    creds = request.json or {}
    username = (creds.get('username') or '').strip()
    password = creds.get('password') or ''
    full_data = load_data()

    if _login_blocked(username):
        return jsonify({"success": False, "message": "Muitas tentativas. Aguarde alguns minutos e tente novamente."}), 429

    user = full_data['users'].get(username)
    if not user or not verify_password(password, user.get('passwordHash', '')):
        _login_record_fail(username)
        return jsonify({"success": False, "message": "Usuário ou senha incorretos."}), 401

    status = user.get('status', 'active')
    if status == 'pending':
        return jsonify({"success": False, "message": "Sua conta está aguardando aprovação do administrador."}), 403
    if status == 'disabled':
        return jsonify({"success": False, "message": "Sua conta foi desativada. Contate o administrador."}), 403

    # Token de sessão aleatório (não é mais o nome de usuário)
    token = _create_session(full_data, username)
    save_data(full_data)
    return jsonify({
        "success": True,
        "token": token,
        "username": username,
        "role": user['role'],
        "firstName": user.get('firstName', ''),
        "lastName": user.get('lastName', ''),
        "mustResetPassword": user.get('mustResetPassword', False)
    })


@app.route('/api/logo', methods=['GET'])
def public_logo():
    """Retorna a logo pública (sem autenticação) para exibir na tela de login."""
    full_data = load_data()
    return jsonify({"logo": full_data.get('globalConfig', {}).get('logo')})


@app.route('/api/logout', methods=['POST'])
def logout():
    token = request.headers.get('Authorization')
    full_data = load_data()
    sessions = full_data.get('sessions') or {}
    if token in sessions:
        del sessions[token]
        save_data(full_data)
    return jsonify({"success": True})


@app.route('/api/register', methods=['POST'])
def register():
    """Cadastro público — cria conta como 'pending' até admin aprovar."""
    data_in = request.json or {}
    username = (data_in.get('username') or '').strip()
    password = data_in.get('password') or ''
    first = (data_in.get('firstName') or '').strip()
    last = (data_in.get('lastName') or '').strip()
    email = (data_in.get('email') or '').strip().lower()
    phone = (data_in.get('phone') or '').strip()

    # Validações
    if not username or not re.match(r'^[a-zA-Z0-9_.-]{3,30}$', username):
        return jsonify({"success": False, "message": "Login inválido. Use 3-30 caracteres (letras, números, . _ -)."}), 400
    if not password or len(password) < 6:
        return jsonify({"success": False, "message": "A senha deve ter no mínimo 6 caracteres."}), 400
    if not first:
        return jsonify({"success": False, "message": "Informe o nome."}), 400
    if not last:
        return jsonify({"success": False, "message": "Informe o sobrenome."}), 400
    if not is_valid_email(email):
        return jsonify({"success": False, "message": "E-mail inválido."}), 400
    if not phone or len(re.sub(r'\D', '', phone)) < 8:
        return jsonify({"success": False, "message": "Telefone inválido."}), 400

    full_data = load_data()
    if username in full_data['users']:
        return jsonify({"success": False, "message": "Esse login já está em uso."}), 400
    for u in full_data['users'].values():
        if u.get('email', '').lower() == email and email:
            return jsonify({"success": False, "message": "Esse e-mail já está cadastrado."}), 400

    full_data['users'][username] = {
        "passwordHash": hash_password(password),
        "role": "user",
        "status": "pending",
        "firstName": first,
        "lastName": last,
        "email": email,
        "phone": phone,
        "mustResetPassword": False,
        "createdAt": datetime.utcnow().isoformat() + "Z"
    }
    save_data(full_data)
    return jsonify({"success": True, "message": "Conta criada! Aguarde a aprovação do administrador."})


@app.route('/api/change-password', methods=['POST'])
def change_password():
    full_data = load_data()
    user = _resolve_token(full_data, request.headers.get('Authorization'))
    if not user:
        return jsonify({"error": "Não autorizado"}), 401

    body = request.json or {}
    current = body.get('currentPassword') or ''
    new = body.get('newPassword') or ''

    u = full_data['users'][user]
    if not verify_password(current, u.get('passwordHash', '')):
        return jsonify({"success": False, "message": "Senha atual incorreta."}), 400
    if len(new) < 6:
        return jsonify({"success": False, "message": "A nova senha deve ter no mínimo 6 caracteres."}), 400

    u['passwordHash'] = hash_password(new)
    u['mustResetPassword'] = False
    save_data(full_data)
    return jsonify({"success": True})


@app.route('/api/data', methods=['GET'])
def get_data():
    full_data = load_data()
    user = _resolve_token(full_data, request.headers.get('Authorization'))

    if not user:
        return jsonify({"error": "Não autorizado"}), 401

    # Inicializa o estado do usuário caso seja o primeiro login dele
    if user not in full_data['userStates']:
        first_model_id = full_data['globalConfig']['models'][0]['id'] if full_data['globalConfig']['models'] else ""
        full_data['userStates'][user] = {
            "headerData": {"date": "", "selectedTemplateId": first_model_id, "showSignatures": True},
            "answers": {},
            "diagramMarks": {},
            "reportImages": [],
            "pdfMargin": "1.5cm"
        }
        save_data(full_data)

    return jsonify({
        "globalConfig": full_data['globalConfig'],
        "userState": full_data['userStates'][user],
        "role": full_data['users'][user]['role']
    })


@app.route('/api/data', methods=['POST'])
def update_data():
    payload = request.json
    full_data = load_data()
    user = _resolve_token(full_data, request.headers.get('Authorization'))

    if not user:
        return jsonify({"error": "Não autorizado"}), 401

    role = full_data['users'][user]['role']

    # O Usuário atualiza apenas o PRÓPRIO estado de laudo
    if 'userState' in payload:
        full_data['userStates'][user] = payload['userState']

    # Apenas Admin pode atualizar as configurações globais (Modelos, Logo, Cabeçalhos)
    if role == 'admin' and 'globalConfig' in payload:
        full_data['globalConfig'] = payload['globalConfig']

    save_data(full_data)
    return jsonify({"status": "success"})


def _set_omie_context(full_data, username):
    """Define no contexto da requisição as credenciais Omie + filial do usuário logado."""
    u = full_data.get('users', {}).get(username, {})
    filial_id = u.get('filialId') or 'matriz'
    filial = (full_data.get('filiais') or {}).get(filial_id) or {}
    g.filial_id = filial_id
    g.omie_app_key = filial.get('omieAppKey') or os.environ.get('OMIE_APP_KEY')
    g.omie_app_secret = filial.get('omieAppSecret') or os.environ.get('OMIE_APP_SECRET')


def _require_admin():
    full_data = load_data()
    user = _resolve_token(full_data, request.headers.get('Authorization'))
    if not user or full_data['users'][user].get('role') != 'admin':
        return None, None, (jsonify({"error": "Não autorizado"}), 401)
    _set_omie_context(full_data, user)
    return user, full_data, None


@app.route('/api/users', methods=['GET', 'POST', 'DELETE'])
def manage_users():
    user, full_data, err = _require_admin()
    if err:
        return err

    if request.method == 'GET':
        users_list = [public_user_view(k, v) for k, v in full_data['users'].items()]
        return jsonify(users_list)

    if request.method == 'POST':
        body = request.json or {}
        new_user = (body.get('username') or '').strip()
        new_pass = body.get('password') or ''
        new_role = body.get('role', 'user')
        first = (body.get('firstName') or '').strip()
        last = (body.get('lastName') or '').strip()
        email = (body.get('email') or '').strip().lower()
        phone = (body.get('phone') or '').strip()
        filial_id = (body.get('filialId') or 'matriz').strip()

        if not new_user or not new_pass:
            return jsonify({"error": "Preencha usuário e senha"}), 400
        if len(new_pass) < 6:
            return jsonify({"error": "A senha deve ter no mínimo 6 caracteres"}), 400
        if new_user in full_data['users']:
            return jsonify({"error": "Usuário já existe"}), 400

        full_data['users'][new_user] = {
            "passwordHash": hash_password(new_pass),
            "role": new_role,
            "status": "active",
            "firstName": first,
            "lastName": last,
            "email": email,
            "phone": phone,
            "mustResetPassword": False,
            "createdAt": datetime.utcnow().isoformat() + "Z",
            "filialId": filial_id
        }
        save_data(full_data)
        return jsonify({"success": True})

    if request.method == 'DELETE':
        target_user = (request.json or {}).get('username')
        if target_user == user:
            return jsonify({"error": "Você não pode excluir a si mesmo"}), 400

        if target_user in full_data['users']:
            del full_data['users'][target_user]
            if target_user in full_data['userStates']:
                del full_data['userStates'][target_user]
            save_data(full_data)

        return jsonify({"success": True})


@app.route('/api/users/<username>/approve', methods=['POST'])
def approve_user(username):
    user, full_data, err = _require_admin()
    if err:
        return err
    if username not in full_data['users']:
        return jsonify({"error": "Usuário não encontrado"}), 404
    full_data['users'][username]['status'] = 'active'
    save_data(full_data)
    return jsonify({"success": True})


@app.route('/api/users/<username>/disable', methods=['POST'])
def disable_user(username):
    user, full_data, err = _require_admin()
    if err:
        return err
    if username == user:
        return jsonify({"error": "Você não pode desativar a si mesmo"}), 400
    if username not in full_data['users']:
        return jsonify({"error": "Usuário não encontrado"}), 404
    full_data['users'][username]['status'] = 'disabled'
    save_data(full_data)
    return jsonify({"success": True})


@app.route('/api/users/<username>/enable', methods=['POST'])
def enable_user(username):
    user, full_data, err = _require_admin()
    if err:
        return err
    if username not in full_data['users']:
        return jsonify({"error": "Usuário não encontrado"}), 404
    full_data['users'][username]['status'] = 'active'
    save_data(full_data)
    return jsonify({"success": True})


@app.route('/api/users/<username>/reset-password', methods=['POST'])
def reset_password(username):
    user, full_data, err = _require_admin()
    if err:
        return err
    if username not in full_data['users']:
        return jsonify({"error": "Usuário não encontrado"}), 404
    temp = generate_temp_password()
    full_data['users'][username]['passwordHash'] = hash_password(temp)
    full_data['users'][username]['mustResetPassword'] = True
    save_data(full_data)
    return jsonify({"success": True, "tempPassword": temp})


@app.route('/api/laudos', methods=['GET', 'POST', 'DELETE'])
def manage_laudos():
    """CRUD de laudos salvos (histórico). Cada usuário tem seus laudos."""
    full_data = load_data()
    user = _resolve_token(full_data, request.headers.get('Authorization'))
    if not user:
        return jsonify({"error": "Não autorizado"}), 401

    if 'laudos' not in full_data:
        full_data['laudos'] = {}
    if user not in full_data['laudos']:
        full_data['laudos'][user] = {}

    if request.method == 'GET':
        summary = []
        for lid, laudo in full_data['laudos'][user].items():
            summary.append({"id": lid, "name": laudo.get("name", "Sem nome"), "date": laudo.get("date", "")})
        # Mais recentes primeiro
        summary.sort(key=lambda x: x.get('date', '') or '', reverse=True)
        return jsonify(summary)

    if request.method == 'POST':
        payload = request.json or {}
        action = payload.get('action', 'save')
        if action == 'save':
            import time
            lid = payload.get('id') or ('laudo_' + str(int(time.time() * 1000)))
            # Externaliza as fotos pra arquivos (JSON fica enxuto)
            state = _externalize_images(user, lid, payload.get('state', {}))
            full_data['laudos'][user][lid] = {
                "id": lid,
                "name": payload.get('name', 'Sem nome'),
                "date": payload.get('date', ''),
                "state": state,
                "savedAt": datetime.utcnow().isoformat() + "Z"
            }
            save_data(full_data)
            return jsonify({"success": True, "id": lid})
        if action == 'load':
            lid = payload.get('id')
            laudo = full_data['laudos'][user].get(lid)
            if not laudo:
                return jsonify({"error": "Laudo não encontrado"}), 404
            # Reinfla as fotos pra base64 (contrato igual ao de antes)
            return jsonify({**laudo, "state": _inflate_images(laudo.get('state') or {})})
        if action == 'duplicate':
            import time
            lid = payload.get('id')
            src = full_data['laudos'][user].get(lid)
            if not src:
                return jsonify({"error": "Laudo não encontrado"}), 404
            new_id = 'laudo_' + str(int(time.time() * 1000))
            # Reinfla o original e re-externaliza sob o novo id (copia os arquivos de foto)
            dup_state = _externalize_images(user, new_id, _inflate_images(src.get('state') or {}))
            full_data['laudos'][user][new_id] = {
                "id": new_id,
                "name": (src.get('name') or 'Sem nome') + ' (Cópia)',
                "date": src.get('date', ''),
                "state": dup_state,
                "savedAt": datetime.utcnow().isoformat() + "Z"
            }
            save_data(full_data)
            return jsonify({"success": True, "id": new_id})

    if request.method == 'DELETE':
        lid = (request.json or {}).get('id')
        if lid and lid in full_data['laudos'][user]:
            del full_data['laudos'][user][lid]
            _delete_laudo_assets(user, lid)
            save_data(full_data)
        return jsonify({"success": True})


@app.route('/api/filiais', methods=['GET', 'POST', 'DELETE'])
def manage_filiais():
    """CRUD de filiais (cada uma com suas credenciais Omie). Apenas admin."""
    user, full_data, err = _require_admin()
    if err:
        return err
    if 'filiais' not in full_data:
        full_data['filiais'] = {}

    if request.method == 'GET':
        # Não vaza os segredos — só indica se está configurado
        out = []
        for fid, f in full_data['filiais'].items():
            out.append({
                "id": fid,
                "nome": f.get('nome', fid),
                "omieConfigured": bool(f.get('omieAppKey') and f.get('omieAppSecret')),
                "usaEnvVar": not bool(f.get('omieAppKey'))
            })
        return jsonify(out)

    if request.method == 'POST':
        body = request.json or {}
        fid = (body.get('id') or '').strip()
        nome = (body.get('nome') or '').strip()
        if not nome:
            return jsonify({"error": "Informe o nome da filial"}), 400
        if not fid:
            fid = 'filial_' + str(int(datetime.utcnow().timestamp()))
        existing = full_data['filiais'].get(fid, {})
        nova = {
            "id": fid,
            "nome": nome,
            # Só atualiza credenciais se foram enviadas (não apaga ao editar só o nome)
            "omieAppKey": body.get('omieAppKey') if body.get('omieAppKey') is not None else existing.get('omieAppKey', ''),
            "omieAppSecret": body.get('omieAppSecret') if body.get('omieAppSecret') is not None else existing.get('omieAppSecret', '')
        }
        full_data['filiais'][fid] = nova
        save_data(full_data)
        return jsonify({"success": True, "id": fid})

    if request.method == 'DELETE':
        fid = (request.json or {}).get('id')
        if fid == 'matriz':
            return jsonify({"error": "Não é possível excluir a Matriz"}), 400
        if fid in full_data['filiais']:
            # Move usuários da filial excluída pra matriz
            for u in full_data['users'].values():
                if u.get('filialId') == fid:
                    u['filialId'] = 'matriz'
            del full_data['filiais'][fid]
            save_data(full_data)
        return jsonify({"success": True})


@app.route('/api/export-config', methods=['GET'])
def export_config():
    """Exporta configs globais + usuários + laudos como JSON (apenas admin)."""
    user, full_data, err = _require_admin()
    if err:
        return err
    return jsonify({
        "globalConfig": full_data.get('globalConfig', {}),
        "users": full_data.get('users', {}),  # cuidado: inclui hashes de senha
        "laudos": _inflate_laudos_map(full_data.get('laudos', {})),  # reinfla fotos -> backup self-contained
        "exportedAt": datetime.utcnow().isoformat() + "Z"
    })


@app.route('/api/import-config', methods=['POST'])
def import_config():
    """Importa configs/usuários/laudos de um JSON (apenas admin). Sobrescreve."""
    user, full_data, err = _require_admin()
    if err:
        return err
    payload = request.json or {}
    if 'globalConfig' in payload:
        full_data['globalConfig'] = payload['globalConfig']
    if 'users' in payload:
        full_data['users'] = payload['users']
    if 'laudos' in payload:
        full_data['laudos'] = payload['laudos']
    if 'userStates' in payload:
        full_data['userStates'] = payload['userStates']
    save_data(full_data)
    return jsonify({"success": True})


@app.route('/api/users/<username>/role', methods=['POST'])
def change_role(username):
    user, full_data, err = _require_admin()
    if err:
        return err
    if username not in full_data['users']:
        return jsonify({"error": "Usuário não encontrado"}), 404
    new_role = (request.json or {}).get('role')
    if new_role not in ('user', 'admin'):
        return jsonify({"error": "Role inválido"}), 400
    if username == user and new_role != 'admin':
        return jsonify({"error": "Você não pode rebaixar a si mesmo"}), 400
    full_data['users'][username]['role'] = new_role
    save_data(full_data)
    return jsonify({"success": True})


@app.route('/api/users/<username>/filial', methods=['POST'])
def change_filial(username):
    user, full_data, err = _require_admin()
    if err:
        return err
    if username not in full_data['users']:
        return jsonify({"error": "Usuário não encontrado"}), 404
    fid = (request.json or {}).get('filialId')
    if fid not in (full_data.get('filiais') or {}):
        return jsonify({"error": "Filial inválida"}), 400
    full_data['users'][username]['filialId'] = fid
    save_data(full_data)
    return jsonify({"success": True})


# ==========================================================
#  INTEGRAÇÃO OMIE
# ==========================================================
OMIE_BASE = "https://app.omie.com.br/api/v1"

# Cache híbrido: em memória + persistido em disco no /data (persistente entre deploys/restarts).
# TTL longo (24h) porque catálogo Omie muda raramente. Usuário pode forçar refresh manual.
OMIE_CACHE_TTL = 86400  # 24 horas


def _omie_cache_path():
    base = os.path.dirname(DATA_FILE) or '.'
    return os.path.join(base, 'omie_cache.json')


def _load_omie_cache():
    path = _omie_cache_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


_omie_cache = _load_omie_cache()
_omie_cache_dirty = False


def _flush_omie_cache():
    """Salva cache em disco. Chamado periodicamente / quando há mudança."""
    global _omie_cache_dirty
    if not _omie_cache_dirty:
        return
    path = _omie_cache_path()
    try:
        tmp = path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(_omie_cache, f, ensure_ascii=False)
        os.replace(tmp, path)
        _omie_cache_dirty = False
    except Exception:
        pass


def _cache_fkey(key):
    """Prefixa a chave de cache com a filial atual (isola catálogos entre filiais)."""
    return f"{getattr(g, 'filial_id', 'matriz')}:{key}"


def _cache_get(key):
    import time
    item = _omie_cache.get(_cache_fkey(key))
    if not item:
        return None
    ts = item.get('ts', 0)
    if time.time() - ts > OMIE_CACHE_TTL:
        return None
    return item.get('data')


def _cache_set(key, payload):
    import time
    global _omie_cache_dirty
    _omie_cache[_cache_fkey(key)] = {'ts': time.time(), 'data': payload}
    _omie_cache_dirty = True
    _flush_omie_cache()


class OmieError(Exception):
    def __init__(self, message, status=502, payload=None):
        super().__init__(message)
        self.status = status
        self.payload = payload


class OmieNoRecords(Exception):
    """Omie retorna erro 500 com 'Não existem registros' quando uma lista vem vazia."""
    pass


def omie_call(endpoint: str, call: str, param: dict, timeout: int = 20):
    """Chama a API Omie. endpoint ex: '/geral/clientes/'. param é um dict (vai virar lista de 1 elemento)."""
    # Usa credenciais da filial do usuário (setadas em g), com fallback pras env vars
    app_key = getattr(g, 'omie_app_key', None) or os.environ.get("OMIE_APP_KEY")
    app_secret = getattr(g, 'omie_app_secret', None) or os.environ.get("OMIE_APP_SECRET")
    if not app_key or not app_secret:
        raise OmieError("Credenciais Omie não configuradas para esta filial.", status=503)

    url = OMIE_BASE + endpoint
    body = json.dumps({
        "call": call,
        "app_key": app_key,
        "app_secret": app_secret,
        "param": [param]
    }).encode('utf-8')

    req = urlreq.Request(url, data=body, headers={'Content-Type': 'application/json'})
    try:
        with urlreq.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode('utf-8')
    except HTTPError as e:
        # Omie devolve erros como HTTP 500 com JSON descritivo
        msg = f"HTTP {e.code}"
        fault = ''
        try:
            err_body = e.read().decode('utf-8')
            err_json = json.loads(err_body)
            fault = err_json.get('faultstring') or err_json.get('faultcode') or err_body
            msg = fault
        except Exception:
            pass
        # Tratamento especial: lista vazia vem como erro
        if fault and ('ERROR-0' in fault or 'não existem registros' in fault.lower() or 'nao existem registros' in fault.lower() or 'no records' in fault.lower()):
            raise OmieNoRecords()
        raise OmieError(f"Omie: {msg}", status=502, payload={"http": e.code})
    except URLError as e:
        raise OmieError(f"Falha de conexão com Omie: {e.reason}", status=502)

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raise OmieError("Resposta inválida do Omie", status=502)


# Nome da categoria do Pedido de Venda usada quando as peças geram venda (cAcaoProdUtilizados="REM").
CATEGORIA_PEDIDO_VENDA_PADRAO = "Serviços de Manutenção de Baterias, Carregadores e Componentes"


def _norm_txt(s):
    """Normaliza texto pra comparação: minúsculo, sem acentos, sem espaços nas pontas."""
    import unicodedata
    s = (s or '').strip().lower()
    return ''.join(c for c in unicodedata.normalize('NFKD', s) if not unicodedata.combining(c))


def get_categoria_pedido_venda_code(nome=None):
    """Resolve o código (ex: '1.01.05') da categoria do Pedido de Venda pelo nome, no Omie.
    Cacheado por filial. Retorna None se não encontrar."""
    nome = nome or CATEGORIA_PEDIDO_VENDA_PADRAO
    cache_key = 'categ_pedvenda:' + nome
    cached = _cache_get(cache_key)
    if cached:
        return cached
    alvo = _norm_txt(nome)
    pagina = 1
    while pagina <= 50:  # trava de segurança
        try:
            data = omie_call('/geral/categorias/', 'ListarCategorias', {
                "pagina": pagina,
                "registros_por_pagina": 100
            })
        except OmieNoRecords:
            break
        cats = data.get('categoria_cadastro') or []
        for c in cats:
            if _norm_txt(c.get('descricao')) == alvo:
                codigo = c.get('codigo')
                if codigo:
                    _cache_set(cache_key, codigo)
                    return codigo
        total_paginas = int(data.get('total_de_paginas') or 1)
        if pagina >= total_paginas or not cats:
            break
        pagina += 1
    return None


def _omie_produtos_all():
    """Lista de produtos do Omie (cacheada por filial): [{id, code, description, unit, unitPrice}]."""
    cache_key = "produtos_full"
    all_items = _cache_get(cache_key)
    if all_items is None:
        all_items = []
        page = 1
        while page <= 20:
            param = {
                "pagina": page,
                "registros_por_pagina": 100,
                "apenas_importado_api": "N",
                "filtrar_apenas_omiepdv": "N"
            }
            try:
                data = omie_call('/geral/produtos/', 'ListarProdutos', param)
            except OmieNoRecords:
                break
            for p in data.get('produto_servico_cadastro', []) or []:
                all_items.append({
                    "id": p.get('codigo_produto'),
                    "code": p.get('codigo') or '',
                    "description": p.get('descricao') or '',
                    "unit": p.get('unidade'),
                    "unitPrice": float(p.get('valor_unitario') or 0)
                })
            total_pages = data.get('total_de_paginas', 1) or 1
            if page >= total_pages:
                break
            page += 1
        _cache_set(cache_key, all_items)
    return all_items


def _enriquece_pecas_omie(parts):
    """Preenche code/description/unitPrice das peças a partir do cadastro de produtos do Omie,
    casando pelo omieProductId (= codigo_produto). Usado na importação de OS."""
    if not parts:
        return parts
    try:
        prod_map = {str(p['id']): p for p in _omie_produtos_all() if p.get('id') is not None}
    except OmieError:
        return parts
    for pc in parts:
        info = prod_map.get(str(pc.get('omieProductId')))
        if info:
            if not pc.get('description'):
                pc['description'] = info.get('description') or ''
            if not pc.get('code'):
                pc['code'] = info.get('code') or ''
            if not pc.get('unitPrice'):
                pc['unitPrice'] = info.get('unitPrice') or 0
    return parts


def _require_user():
    full_data = load_data()
    user = _resolve_token(full_data, request.headers.get('Authorization'))
    if not user:
        return None, None, (jsonify({"error": "Não autorizado"}), 401)
    if full_data['users'][user].get('status') != 'active':
        return None, None, (jsonify({"error": "Conta inativa"}), 403)
    _set_omie_context(full_data, user)
    return user, full_data, None


@app.route('/api/omie/debug/servicos', methods=['GET'])
def omie_debug_servicos():
    """Retorna a resposta crua da Omie para inspecionarmos a estrutura."""
    user, full_data, err = _require_admin()
    if err:
        return err
    try:
        data = omie_call('/servicos/servico/', 'ListarCadastroServico', {
            "nPagina": 1,
            "nRegPorPagina": 3
        })
        return jsonify(data)
    except OmieNoRecords:
        return jsonify({"empty": True})
    except OmieError as e:
        return jsonify({"error": str(e)}), e.status


@app.route('/api/omie/debug/contacorrente', methods=['GET'])
def omie_debug_cc():
    user, full_data, err = _require_user()
    if err:
        return err
    try:
        data = omie_call('/geral/contacorrente/', 'ListarContasCorrentes', {
            "pagina": 1,
            "registros_por_pagina": 5,
            "apenas_importado_api": "N"
        })
        return jsonify(data)
    except OmieError as e:
        return jsonify({"error": str(e)}), e.status


@app.route('/api/omie/debug/listaros', methods=['GET'])
def omie_debug_listaros():
    user, full_data, err = _require_user()
    if err:
        return err
    try:
        data = omie_call('/servicos/os/', 'ListarOS', {
            "pagina": 1,
            "registros_por_pagina": 3,
            "apenas_importado_api": "N"
        })
        return jsonify(data)
    except OmieError as e:
        return jsonify({"error": str(e)}), e.status


# ===== CRM / Oportunidades — Fase 1: descoberta da estrutura real =====
@app.route('/api/omie/debug/oportunidades', methods=['GET'])
def omie_debug_oportunidades():
    """DESCOBERTA: lista oportunidades cruas do CRM Omie pra inspecionarmos os campos
    reais (código da fase '01 - Em Análise', dados de cliente/contato, ticket).
    Aceita ?pagina=, ?registros= e ?fase= (opcional) na query string."""
    user, full_data, err = _require_user()
    if err:
        return err
    pagina = int(request.args.get('pagina', 1))
    registros = int(request.args.get('registros', 20))
    param = {
        "pagina": pagina,
        "registros_por_pagina": registros,
        "apenas_importado_api": "N"
    }
    # Filtro de fase é opcional — só inclui se passado, pra primeiro vermos tudo
    fase = request.args.get('fase')
    if fase:
        param["fase"] = int(fase)
    try:
        data = omie_call('/crm/oportunidades/', 'ListarOportunidades', param)
        return jsonify(data)
    except OmieNoRecords:
        return jsonify({"empty": True, "msg": "Nenhuma oportunidade encontrada nessa página/fase."})
    except OmieError as e:
        return jsonify({"error": str(e), "param_enviado": param}), e.status


@app.route('/api/omie/debug/oportunidade/<cod>', methods=['GET'])
def omie_debug_oportunidade(cod):
    """DESCOBERTA: consulta uma oportunidade específica pra ver TODOS os campos
    (incluindo o ticket detalhado). Tenta nCodOp; se a Omie reclamar do nome,
    o erro retornado nos diz o campo correto."""
    user, full_data, err = _require_user()
    if err:
        return err
    try:
        data = omie_call('/crm/oportunidades/', 'ConsultarOportunidade', {
            "nCodOp": int(cod)
        })
        return jsonify(data)
    except OmieError as e:
        return jsonify({"error": str(e)}), e.status


@app.route('/api/omie/debug/call', methods=['GET'])
def omie_debug_call():
    """DESCOBERTA GENÉRICA (admin): chama qualquer endpoint/método do Omie.
    Uso: ?endpoint=/crm/fases/&call=ListarFases&param={...json...}
    Permite explorar a API sem precisar de novo deploy a cada tentativa."""
    user, full_data, err = _require_admin()
    if err:
        return err
    endpoint = request.args.get('endpoint')
    call = request.args.get('call')
    param_json = request.args.get('param', '{}')
    if not endpoint or not call:
        return jsonify({"error": "Informe ?endpoint=/crm/fases/&call=ListarFases&param={}"}), 400
    try:
        param = json.loads(param_json)
    except Exception:
        return jsonify({"error": "param não é JSON válido", "recebido": param_json}), 400
    try:
        data = omie_call(endpoint, call, param)
        return jsonify(data)
    except OmieNoRecords:
        return jsonify({"empty": True, "msg": "Sem registros."})
    except OmieError as e:
        return jsonify({"error": str(e), "endpoint": endpoint, "call": call, "param": param}), e.status


@app.route('/api/omie/os/abertas', methods=['GET'])
def omie_os_abertas():
    """Lista OSes do Omie que ainda não foram faturadas/canceladas, pra técnico importar e editar."""
    user, full_data, err = _require_user()
    if err:
        return err
    try:
        all_items = []
        total_paginas = None
        # Vai da última página pra primeira (Omie retorna OSes em ordem cronológica - antigas primeiro)
        # Primeiro chama página 1 só pra descobrir total_de_paginas, depois vai do fim
        first = omie_call('/servicos/os/', 'ListarOS', {
            "pagina": 1,
            "registros_por_pagina": 50,
            "apenas_importado_api": "N"
        })
        total_paginas = first.get('total_de_paginas') or 1

        # Pega últimas 5 páginas (mais recentes ~250 OSes)
        paginas_a_buscar = list(range(max(1, total_paginas - 4), total_paginas + 1))
        # Inclui o resultado da página 1 só se total_paginas <= 5
        respostas = []
        if total_paginas <= 5:
            respostas.append(first)
            paginas_a_buscar = [p for p in paginas_a_buscar if p != 1]
        for p in paginas_a_buscar:
            try:
                resp = omie_call('/servicos/os/', 'ListarOS', {
                    "pagina": p,
                    "registros_por_pagina": 50,
                    "apenas_importado_api": "N"
                })
                respostas.append(resp)
            except OmieNoRecords:
                continue

        for data in respostas:
            for o in data.get('osCadastro') or []:
                cab = o.get('Cabecalho') or {}
                info_cad = o.get('InfoCadastro') or {}
                info_adic = o.get('InformacoesAdicionais') or {}
                obs = o.get('Observacoes') or {}
                # Pula faturadas e canceladas
                if (info_cad.get('cFaturada') or 'N').upper() == 'S':
                    continue
                if (info_cad.get('cCancelada') or 'N').upper() == 'S':
                    continue
                all_items.append({
                    "nCodOS": cab.get('nCodOS'),
                    "cNumOS": cab.get('cNumOS'),
                    "nCodCli": cab.get('nCodCli'),
                    "cCodIntOS": cab.get('cCodIntOS'),
                    "cEtapa": cab.get('cEtapa') or '',
                    "nValorTotal": cab.get('nValorTotal') or 0,
                    "dDtPrevisao": cab.get('dDtPrevisao'),
                    "dDtInc": info_cad.get('dDtInc'),
                    "cContato": (info_adic.get('cContato') or '')[:60],
                    "cObs": ((obs.get('cObsOS') if isinstance(obs, dict) else '') or info_adic.get('cDadosAdicNF') or '')[:100]
                })

        # Ordena por dDtInc descendente (mais recente primeiro)
        def _date_key(o):
            d = o.get('dDtInc') or ''
            try:
                return datetime.strptime(d, '%d/%m/%Y')
            except Exception:
                return datetime.min
        all_items.sort(key=_date_key, reverse=True)
        all_items = all_items[:80]

        # Enriquece com nome do cliente (cache por cliente)
        unique_cli_ids = list({i['nCodCli'] for i in all_items if i.get('nCodCli')})
        for cli_id in unique_cli_ids:
            ck = f"cli_name_{cli_id}"
            if _cache_get(ck) is None:
                try:
                    cli_data = omie_call('/geral/clientes/', 'ConsultarCliente', {"codigo_cliente_omie": cli_id})
                    nome = cli_data.get('razao_social') or cli_data.get('nome_fantasia') or ''
                    _cache_set(ck, nome or '—')
                except OmieError:
                    _cache_set(ck, '—')
        for i in all_items:
            if i.get('nCodCli'):
                i['clientName'] = _cache_get(f"cli_name_{i['nCodCli']}") or ''

        return jsonify({"items": all_items, "totalPaginas": total_paginas})
    except OmieError as e:
        return jsonify({"error": str(e)}), e.status


@app.route('/api/omie/os/<int:nCodOS>', methods=['GET'])
def omie_os_consulta(nCodOS):
    """Consulta uma OS específica no Omie e retorna em formato compatível com nosso rascunho."""
    user, full_data, err = _require_user()
    if err:
        return err
    try:
        data = omie_call('/servicos/os/', 'ConsultarOS', {"nCodOS": nCodOS})
        cab = data.get('Cabecalho') or {}
        info = data.get('InformacoesAdicionais') or {}
        servicos_omie = data.get('ServicosPrestados') or []
        produtos_omie = (data.get('produtosUtilizados') or {}).get('produtoUtilizado') or []

        # Consulta cliente pra nome
        client_name = ''
        client_doc = ''
        if cab.get('nCodCli'):
            try:
                cli_data = omie_call('/geral/clientes/', 'ConsultarCliente', {"codigo_cliente_omie": cab['nCodCli']})
                client_name = cli_data.get('razao_social') or cli_data.get('nome_fantasia') or ''
                client_doc = cli_data.get('cnpj_cpf') or ''
            except OmieError:
                pass

        # Mapeia serviços Omie -> nosso formato
        servicos = []
        for s in servicos_omie:
            servicos.append({
                "omieServiceId": s.get('nCodServico'),
                "code": '',
                "description": s.get('cDescServ') or '',
                "quantity": float(s.get('nQtde') or 1),
                "unitPrice": float(s.get('nValUnit') or 0),
                "cTribServ": s.get('cTribServ') or '01',
                "cCodServMun": s.get('cCodServMun') or '',
                "cCodLC116": s.get('cCodServLC116') or ''
            })

        # Mapeia produtos Omie -> peças
        parts = []
        for p in produtos_omie:
            parts.append({
                "omieProductId": p.get('nCodProdutoPU'),
                "code": '',
                "description": '',
                "quantity": float(p.get('nQtdePU') or 1),
                "unitPrice": 0
            })
        _enriquece_pecas_omie(parts)

        return jsonify({
            "omieOsId": cab.get('nCodOS'),
            "omieOsNumber": cab.get('cNumOS'),
            "cEtapa": cab.get('cEtapa'),
            "client": {
                "omieClientId": cab.get('nCodCli'),
                "name": client_name,
                "document": client_doc,
                "email": "",
                "phone": ""
            },
            "services": servicos,
            "parts": parts,
            "observations": info.get('cDadosAdicNF', ''),
            "informacoesAdicionais": {
                "cCodCateg": info.get('cCodCateg'),
                "nCodCC": info.get('nCodCC')
            }
        })
    except OmieError as e:
        return jsonify({"error": str(e)}), e.status


@app.route('/api/os/importar-omie', methods=['POST'])
def os_importar_omie():
    """Importa uma OS do Omie como rascunho local (pra editar e depois salvar de volta com AlterarOS)."""
    user, full_data, err = _require_user()
    if err:
        return err
    body = request.json or {}
    nCodOS = body.get('nCodOS')
    if not nCodOS:
        return jsonify({"error": "nCodOS obrigatório"}), 400

    # Consulta no Omie
    try:
        data = omie_call('/servicos/os/', 'ConsultarOS', {"nCodOS": int(nCodOS)})
    except OmieError as e:
        return jsonify({"error": str(e)}), e.status

    cab = data.get('Cabecalho') or {}
    info = data.get('InformacoesAdicionais') or {}
    servicos_omie = data.get('ServicosPrestados') or []
    produtos_omie = (data.get('produtosUtilizados') or {}).get('produtoUtilizado') or []

    # Verifica se já tem rascunho linkado a essa OS em qualquer usuário da filial
    existing = next((d for _o, d in _all_filial_drafts(full_data, user) if d.get('omieOsId') == cab.get('nCodOS')), None)
    if existing:
        return jsonify(existing)
    drafts = _user_drafts(full_data, user)  # importa para o próprio usuário

    client_name = ''
    client_doc = ''
    if cab.get('nCodCli'):
        try:
            cli_data = omie_call('/geral/clientes/', 'ConsultarCliente', {"codigo_cliente_omie": cab['nCodCli']})
            client_name = cli_data.get('razao_social') or cli_data.get('nome_fantasia') or ''
            client_doc = cli_data.get('cnpj_cpf') or ''
        except OmieError:
            pass

    servicos = []
    for s in servicos_omie:
        servicos.append({
            "omieServiceId": s.get('nCodServico'),
            "code": '',
            "description": s.get('cDescServ') or '',
            "quantity": float(s.get('nQtde') or 1),
            "unitPrice": float(s.get('nValUnit') or 0),
            "cTribServ": s.get('cTribServ') or '01',
            "cCodServMun": s.get('cCodServMun') or '',
            "cCodLC116": s.get('cCodServLC116') or '',
            "nIdItem": s.get('nIdItem'),
            "nSeqItem": s.get('nSeqItem')
        })

    parts = []
    for p in produtos_omie:
        parts.append({
            "omieProductId": p.get('nCodProdutoPU'),
            "code": '',
            "description": '',
            "quantity": float(p.get('nQtdePU') or 1),
            "unitPrice": 0,
            "nIdItem": p.get('nIdItem')
        })
    _enriquece_pecas_omie(parts)

    now = datetime.utcnow().isoformat() + "Z"
    draft = {
        "id": "os_omie_" + str(cab.get('nCodOS')),
        "createdAt": now,
        "updatedAt": now,
        "createdBy": user,
        "fromLaudo": None,
        "client": {
            "omieClientId": cab.get('nCodCli'),
            "name": client_name,
            "document": client_doc,
            "email": "",
            "phone": ""
        },
        "services": servicos,
        "parts": parts,
        "observations": info.get('cDadosAdicNF', ''),
        "status": "imported",  # importada, ainda não atualizada
        "omieOsId": cab.get('nCodOS'),
        "omieOsNumber": cab.get('cNumOS'),
        "importedAt": now,
        "sentAt": None,
        "sendError": None,
        "cCodCategFromOmie": info.get('cCodCateg'),
        "nCodCCFromOmie": info.get('nCodCC'),
        "cCodIntOSOriginal": cab.get('cCodIntOS') or ''
    }
    drafts.append(draft)
    save_data(full_data)
    return jsonify(draft)


@app.route('/api/omie/cache/clear', methods=['POST'])
def omie_clear_cache():
    user, full_data, err = _require_user()
    if err:
        return err
    global _omie_cache_dirty
    _omie_cache.clear()
    _omie_cache_dirty = True
    _flush_omie_cache()
    # Apaga o arquivo do disco também
    try:
        if os.path.exists(_omie_cache_path()):
            os.remove(_omie_cache_path())
    except Exception:
        pass
    return jsonify({"success": True})


@app.route('/api/omie/cache/info', methods=['GET'])
def omie_cache_info():
    """Mostra resumo do que está em cache + idade de cada item."""
    user, full_data, err = _require_user()
    if err:
        return err
    import time
    info = []
    now = time.time()
    for k, v in _omie_cache.items():
        age = int(now - v.get('ts', 0))
        # Não devolve o payload, só metadata
        item_count = None
        data = v.get('data')
        if isinstance(data, list):
            item_count = len(data)
        elif isinstance(data, dict):
            item_count = len(data)
        info.append({
            "key": k,
            "age_seconds": age,
            "age_hours": round(age / 3600, 1),
            "expired": age > OMIE_CACHE_TTL,
            "items": item_count,
            "type": type(data).__name__
        })
    info.sort(key=lambda x: x['age_seconds'])
    return jsonify({"entries": info, "ttl_seconds": OMIE_CACHE_TTL, "path": _omie_cache_path()})


@app.route('/api/omie/webhook', methods=['POST'])
def omie_webhook():
    """Recebe webhooks do Omie. Público (Omie chama sem header de auth). Validamos pelo appKey
    do payload. Sempre responde 200 (pra não bagunçar a fila de webhooks do Omie). Atualiza
    o status do rascunho correspondente quando reconhecemos o evento de OS."""
    import sys
    try:
        payload = request.get_json(silent=True) or {}
    except Exception:
        payload = {}

    topic = (payload.get('topic') or '').strip()
    msg_id = (payload.get('messageId') or '').strip()
    app_key = (payload.get('appKey') or '').strip()
    event = payload.get('event') or {}
    print(f"[OMIE-WEBHOOK] topic={topic!r} msg={msg_id!r} keys={list(event.keys())[:10]}", flush=True)

    # Handshake / ping: Omie envia um ping pra validar o endpoint. Responde 200 e pronto.
    if 'ping' in payload or topic.lower() in ('ping', 'omie.ping') or not event:
        return jsonify({"ok": True, "pong": True})

    full_data = load_data()

    # Validação:
    # 1) Se OMIE_WEBHOOK_TOKEN estiver setado, exigimos que o token bata (mais seguro).
    #    O Omie envia o token configurado em "endpoint_token" no portal do dev.
    expected_tok = (os.environ.get('OMIE_WEBHOOK_TOKEN') or '').strip()
    if expected_tok:
        got_tok = (request.headers.get('X-Omie-Webhook-Token')
                   or payload.get('endpoint_token')
                   or payload.get('endpointToken')
                   or payload.get('token') or '').strip()
        if got_tok != expected_tok:
            print(f"[OMIE-WEBHOOK] endpoint_token invalido — ignorando", flush=True)
            return jsonify({"ok": True, "ignored": "token"})
    # 2) Caso não tenha token configurado, valida via appKey conhecido (fallback).
    else:
        if not _appkey_filial_match(full_data, app_key):
            print(f"[OMIE-WEBHOOK] appKey desconhecido — ignorando", flush=True)
            return jsonify({"ok": True, "ignored": "appKey desconhecido"})

    # Idempotência: descarta messageId já processado (guarda os últimos 200)
    seen = full_data.setdefault('webhooksSeen', [])
    if msg_id and msg_id in seen:
        return jsonify({"ok": True, "duplicate": True})

    # Extrai identificadores comuns da OS
    n_cod_os = (event.get('idOrdemServico') or event.get('nCodOS')
                or event.get('codigo_os') or event.get('codigo_ordem_servico'))
    c_num_os = (event.get('numeroOrdemServico') or event.get('cNumOS')
                or event.get('numero_os') or event.get('numero_ordem_servico'))

    owner, draft = _find_draft_by_omie(full_data, n_cod_os, c_num_os)
    if not draft:
        print(f"[OMIE-WEBHOOK] OS nao localizada (nCodOS={n_cod_os} cNumOS={c_num_os})", flush=True)
        if msg_id:
            seen.append(msg_id); seen[:] = seen[-200:]
            save_data(full_data)
        return jsonify({"ok": True, "matched": False})

    # Mapeia o tópico pra um status amigável
    tl = topic.lower()
    if 'faturad' in tl:
        draft['omieStatus'] = 'faturada'
    elif 'cancel' in tl:
        draft['omieStatus'] = 'cancelada'
    elif 'exclu' in tl:
        draft['omieStatus'] = 'excluida'
    elif 'alterad' in tl or 'etapa' in tl:
        draft['omieStatus'] = 'alterada'
    else:
        draft['omieStatus'] = topic or 'evento'
    draft['omieTopic'] = topic
    draft['omieEventAt'] = datetime.utcnow().isoformat() + "Z"

    if msg_id:
        seen.append(msg_id); seen[:] = seen[-200:]
    save_data(full_data)
    return jsonify({"ok": True, "matched": True, "status": draft['omieStatus']})


@app.route('/api/omie/status', methods=['GET'])
def omie_status():
    """Verifica se as credenciais estão configuradas e se conseguimos chamar o Omie."""
    user, full_data, err = _require_user()
    if err:
        return err
    has_key = bool(os.environ.get("OMIE_APP_KEY"))
    has_secret = bool(os.environ.get("OMIE_APP_SECRET"))
    if not has_key or not has_secret:
        return jsonify({"configured": False, "ok": False, "message": "Credenciais Omie não configuradas no servidor."})
    # Faz um ping de baixo custo: lista 1 cliente
    try:
        omie_call('/geral/clientes/', 'ListarClientes', {
            "pagina": 1,
            "registros_por_pagina": 1,
            "apenas_importado_api": "N"
        })
        return jsonify({"configured": True, "ok": True})
    except OmieError as e:
        return jsonify({"configured": True, "ok": False, "message": str(e)}), e.status


@app.route('/api/omie/clientes', methods=['GET'])
def omie_clientes():
    user, full_data, err = _require_user()
    if err:
        return err
    q = (request.args.get('q') or '').strip()
    page = int(request.args.get('page', 1))
    try:
        param = {
            "pagina": page,
            "registros_por_pagina": 50,
            "apenas_importado_api": "N"
        }
        # Se a busca contém wildcard %, faz busca ampla e filtra em memória.
        # Senão, usa o filtro nativo do Omie pela razão social.
        if q and '%' not in q:
            param["clientesFiltro"] = {"razao_social": q}
        data = omie_call('/geral/clientes/', 'ListarClientes', param)
        clientes = []
        for c in data.get('clientes_cadastro', []):
            name = c.get('razao_social') or c.get('nome_fantasia') or ''
            fantasia = c.get('nome_fantasia') or ''
            if q and '%' in q:
                if not (_matches_wildcard(name, q) or _matches_wildcard(fantasia, q)):
                    continue
            clientes.append({
                "id": c.get('codigo_cliente_omie'),
                "code": c.get('codigo_cliente_integracao'),
                "name": name,
                "fantasia": fantasia,
                "document": c.get('cnpj_cpf'),
                "email": c.get('email'),
                "phone": c.get('telefone1_numero')
            })
        return jsonify({
            "items": clientes,
            "page": data.get('pagina', page),
            "totalPages": data.get('total_de_paginas', 1),
            "totalRegisters": data.get('total_de_registros', len(clientes))
        })
    except OmieNoRecords:
        return jsonify({"items": [], "totalRegisters": 0})
    except OmieError as e:
        return jsonify({"error": str(e)}), e.status


@app.route('/api/omie/clientes', methods=['POST'])
def omie_criar_cliente():
    user, full_data, err = _require_user()
    if err:
        return err
    body = request.json or {}
    try:
        param = {
            "codigo_cliente_integracao": body.get('code') or f"BIO-{int(datetime.utcnow().timestamp())}",
            "razao_social": body.get('name') or '',
            "nome_fantasia": body.get('fantasia') or body.get('name') or '',
            "cnpj_cpf": body.get('document') or '',
            "email": body.get('email') or '',
            "telefone1_numero": body.get('phone') or ''
        }
        if not param["razao_social"]:
            return jsonify({"error": "Nome/Razão social é obrigatório"}), 400
        result = omie_call('/geral/clientes/', 'IncluirCliente', param)
        return jsonify({
            "success": True,
            "id": result.get('codigo_cliente_omie'),
            "code": result.get('codigo_cliente_integracao')
        })
    except OmieError as e:
        return jsonify({"error": str(e)}), e.status


def _norm_text(s):
    """Lowercase + remove acentos."""
    import unicodedata
    s = unicodedata.normalize('NFD', (s or '').lower())
    return ''.join(c for c in s if unicodedata.category(c) != 'Mn')


def _matches_wildcard(text, query):
    """Compara query (com '%' como wildcard) contra text. Cada parte separada por % deve aparecer em ordem."""
    if not query:
        return True
    text_norm = _norm_text(text)
    parts = [_norm_text(p) for p in query.split('%') if p.strip()]
    if not parts:
        return True
    pos = 0
    for p in parts:
        idx = text_norm.find(p, pos)
        if idx == -1:
            return False
        pos = idx + len(p)
    return True


@app.route('/api/omie/servicos', methods=['GET'])
def omie_servicos():
    user, full_data, err = _require_user()
    if err:
        return err
    q = (request.args.get('q') or '').strip()

    try:
        # Pega catálogo COMPLETO do cache (uma vez a cada 5 min), filtra em memória
        cache_key = "servicos_full"
        all_items = _cache_get(cache_key)
        if all_items is None:
            all_items = []
            page = 1
            max_pages = 20
            while page <= max_pages:
                try:
                    data = omie_call('/servicos/servico/', 'ListarCadastroServico', {
                        "nPagina": page,
                        "nRegPorPagina": 100
                    })
                except OmieNoRecords:
                    break
                # Estrutura real do Omie /servicos/servico/:
                # cadastros: [{ cabecalho: {cCodigo, cDescricao, nPrecoUnit, cIdTrib, cCodServMun, cCodLC116}, intListar: {nCodServ}, ... }]
                registros = data.get('cadastros') or []
                for s in registros:
                    cab = s.get('cabecalho') or {}
                    intl = s.get('intListar') or {}
                    descbloco = s.get('descricao') or {}
                    all_items.append({
                        "id": intl.get('nCodServ'),
                        "code": cab.get('cCodigo') or '',
                        "description": (cab.get('cDescricao')
                                        or descbloco.get('cDescrCompleta')
                                        or ''),
                        "unitPrice": float(cab.get('nPrecoUnit') or 0),
                        # Campos fiscais necessários ao IncluirOS:
                        "cTribServ": cab.get('cIdTrib') or '01',
                        "cCodServMun": cab.get('cCodServMun') or '',
                        "cCodLC116": cab.get('cCodLC116') or '',
                        "cCodCateg": cab.get('cCodCateg') or ''
                    })
                total_pages = data.get('nTotPaginas') or 1
                if page >= total_pages:
                    break
                page += 1
            _cache_set(cache_key, all_items)

        # Filtra em memória usando wildcard (%) na busca
        if q:
            filtered = [s for s in all_items if _matches_wildcard(s['description'], q) or _matches_wildcard(s['code'] or '', q)]
        else:
            filtered = all_items
        return jsonify({
            "items": filtered[:50],
            "totalFound": len(filtered),
            "cached": True
        })
    except OmieError as e:
        return jsonify({"error": str(e)}), e.status


@app.route('/api/omie/produtos', methods=['GET'])
def omie_produtos():
    user, full_data, err = _require_user()
    if err:
        return err
    q = (request.args.get('q') or '').strip()

    try:
        all_items = _omie_produtos_all()

        if q:
            filtered = [p for p in all_items if _matches_wildcard(p['description'], q) or _matches_wildcard(p['code'] or '', q)]
        else:
            filtered = all_items
        return jsonify({
            "items": filtered[:50],
            "totalFound": len(filtered),
            "cached": True
        })
    except OmieError as e:
        return jsonify({"error": str(e)}), e.status


# ==========================================================
#  ORDEM DE SERVIÇO - rascunhos locais + envio pro Omie
# ==========================================================
def _user_drafts(full_data, user):
    """Garante que o userState tem osDrafts e retorna a lista."""
    if user not in full_data['userStates']:
        full_data['userStates'][user] = {}
    if 'osDrafts' not in full_data['userStates'][user]:
        full_data['userStates'][user]['osDrafts'] = []
    return full_data['userStates'][user]['osDrafts']


def _responsavel_nome(full_data, username):
    """Nome amigável de um usuário (pra mostrar 'quem preencheu')."""
    u = (full_data.get('users') or {}).get(username) or {}
    nome = f"{u.get('firstName', '')} {u.get('lastName', '')}".strip()
    return nome or username


def _all_filial_drafts(full_data, requesting_user):
    """Retorna [(owner_username, draft)] de TODOS os usuários da mesma filial do requisitante
    (painel de controle compartilhado por filial)."""
    users = full_data.get('users', {})
    my_fil = (users.get(requesting_user) or {}).get('filialId') or 'matriz'
    out = []
    for uname, ustate in (full_data.get('userStates') or {}).items():
        if (users.get(uname) or {}).get('filialId', 'matriz') != my_fil:
            continue
        for d in (ustate.get('osDrafts') or []):
            out.append((uname, d))
    return out


def _find_filial_draft(full_data, requesting_user, os_id):
    """Localiza um rascunho pelo id em qualquer usuário da filial. Retorna (owner, draft) ou (None, None)."""
    for owner, d in _all_filial_drafts(full_data, requesting_user):
        if d.get('id') == os_id:
            return owner, d
    return None, None


def _find_draft_by_omie(full_data, n_cod_os=None, c_num_os=None):
    """Localiza um rascunho pelo nCodOS ou cNumOS do Omie, em QUALQUER usuário (uso interno: webhook)."""
    n_cod_os = int(n_cod_os) if (n_cod_os not in (None, '')) else None
    c_num_os = str(c_num_os) if (c_num_os not in (None, '')) else None
    for uname, ustate in (full_data.get('userStates') or {}).items():
        for d in (ustate.get('osDrafts') or []):
            if n_cod_os is not None and d.get('omieOsId') == n_cod_os:
                return uname, d
            if c_num_os is not None and str(d.get('omieOsNumber') or '') == c_num_os:
                return uname, d
    return None, None


def _appkey_filial_match(full_data, app_key):
    """Verifica se o appKey do webhook bate com alguma filial (matriz usa env)."""
    if not app_key:
        return None
    env_key = os.environ.get('OMIE_APP_KEY') or ''
    for fid, f in (full_data.get('filiais') or {}).items():
        fkey = (f.get('omieAppKey') or '').strip() or env_key
        if fkey and fkey == app_key:
            return fid
    return None


@app.route('/api/os', methods=['GET'])
def os_list():
    user, full_data, err = _require_user()
    if err:
        return err
    # Painel compartilhado: todas as OS da filial, com nome de quem preencheu.
    out = []
    for owner, d in _all_filial_drafts(full_data, user):
        out.append({**d, "responsavel": _responsavel_nome(full_data, d.get('createdBy') or owner)})
    # Ordena por data de criação (mais recente primeiro)
    out.sort(key=lambda x: x.get('createdAt') or '', reverse=True)
    return jsonify(out)


@app.route('/api/os', methods=['POST'])
def os_create():
    user, full_data, err = _require_user()
    if err:
        return err
    body = request.json or {}
    now = datetime.utcnow().isoformat() + "Z"
    draft = {
        "id": "os_" + str(int(datetime.utcnow().timestamp() * 1000)) + "_" + secrets.token_hex(3),
        "createdAt": now,
        "updatedAt": now,
        "createdBy": user,
        "fromLaudo": body.get('fromLaudo') or None,
        "client": body.get('client') or {"omieClientId": None, "name": "", "document": "", "email": "", "phone": ""},
        "services": body.get('services') or [],
        "parts": body.get('parts') or [],
        "observations": body.get('observations') or '',
        "status": "draft",
        "omieOsId": None,
        "omieOsNumber": None,
        "sentAt": None,
        "sendError": None
    }
    drafts = _user_drafts(full_data, user)
    drafts.append(draft)
    save_data(full_data)
    return jsonify(draft)


@app.route('/api/os/<os_id>', methods=['PUT'])
def os_update(os_id):
    user, full_data, err = _require_user()
    if err:
        return err
    body = request.json or {}
    owner, d = _find_filial_draft(full_data, user, os_id)
    if not d:
        return jsonify({"error": "Rascunho não encontrado"}), 404
    if d['status'] == 'sent':
        return jsonify({"error": "OS já enviada não pode ser editada"}), 400
    for k in ('client', 'services', 'parts', 'observations', 'fromLaudo'):
        if k in body:
            d[k] = body[k]
    d['updatedAt'] = datetime.utcnow().isoformat() + "Z"
    save_data(full_data)
    return jsonify(d)


@app.route('/api/os/<os_id>', methods=['DELETE'])
def os_delete(os_id):
    user, full_data, err = _require_user()
    if err:
        return err
    owner, d = _find_filial_draft(full_data, user, os_id)
    if owner:
        full_data['userStates'][owner]['osDrafts'] = [
            x for x in full_data['userStates'][owner]['osDrafts'] if x.get('id') != os_id
        ]
        save_data(full_data)
    return jsonify({"success": True})


@app.route('/api/os/<os_id>/debug', methods=['GET'])
def os_debug(os_id):
    user, full_data, err = _require_user()
    if err:
        return err
    owner, draft = _find_filial_draft(full_data, user, os_id)
    if not draft:
        return jsonify({"error": "draft not found", "available_ids": [d['id'] for _, d in _all_filial_drafts(full_data, user)]}), 404
    return jsonify({
        "draft_id": draft.get('id'),
        "omieOsId": draft.get('omieOsId'),
        "omieOsId_type": type(draft.get('omieOsId')).__name__,
        "omieOsNumber": draft.get('omieOsNumber'),
        "status": draft.get('status'),
        "is_update_calc": bool(draft.get('omieOsId'))
    })


@app.route('/api/gerar-texto-ia', methods=['POST'])
def gerar_texto_ia():
    """Usa o Gemini pra elaborar um texto técnico do laudo a partir dos defeitos encontrados."""
    user, full_data, err = _require_user()
    if err:
        return err

    api_key = os.environ.get('GEMINI_API_KEY')
    if not api_key:
        return jsonify({"error": "GEMINI_API_KEY não configurada no servidor."}), 503

    body = request.json or {}
    header_data = body.get('headerData', {})
    header_config = body.get('headerConfig', [])
    answers = body.get('answers', {})
    questions = body.get('questions', [])
    cell_summary = body.get('cellSummary')  # texto pronto do resumo de células (opcional)
    model_name = body.get('modelName', '')

    # Monta a lista de achados
    achados = []
    for q in questions:
        ans = answers.get(q.get('id'), {}) or {}
        checked = ans.get('checked')
        qtype = q.get('type', 'checkbox')
        if qtype == 'text':
            if ans.get('text'):
                achados.append(f"- {q.get('label')}: {ans.get('text')}")
        elif checked:
            if qtype == 'checkbox_qty':
                achados.append(f"- {q.get('label')}: {ans.get('qty','?')} unidade(s)")
            elif qtype == 'checkbox_text':
                achados.append(f"- {q.get('label')}: {ans.get('text','constatado')}")
            else:
                achados.append(f"- {q.get('label')}: constatado")

    # Dados gerais
    info_lines = []
    for f in header_config:
        val = header_data.get(f.get('id', ''), '')
        if val:
            info_lines.append(f"{f.get('label')}: {val}")

    achados_txt = "\n".join(achados) if achados else "Nenhum defeito assinalado no checklist."
    info_txt = "\n".join(info_lines) if info_lines else "Não informado."
    cell_txt = f"\n\nAnálise de células:\n{cell_summary}" if cell_summary else ""

    from datetime import datetime as _dt
    data_hoje = _dt.now().strftime('%d de %B de %Y')
    meses = {'January':'janeiro','February':'fevereiro','March':'março','April':'abril','May':'maio','June':'junho','July':'julho','August':'agosto','September':'setembro','October':'outubro','November':'novembro','December':'dezembro'}
    for en, pt in meses.items():
        data_hoje = data_hoje.replace(en, pt)

    prompt = f"""Você é um técnico especialista do Laboratório BioDron - Soluções Tecnológicas, especializado em manutenção de baterias inteligentes de drones agrícolas DJI Agras.

Elabore um LAUDO TÉCNICO DE DIAGNÓSTICO E ANÁLISE completo e profissional, em português do Brasil, com tom técnico e comercial, seguindo EXATAMENTE a estrutura do modelo abaixo. Para CADA defeito ou condição encontrada, explique a CONSEQUÊNCIA técnica e o RISCO de não corrigir (ex: adesivo danificado expõe a placa BMS a contaminação e infiltração; borrachas faltando comprometem a vedação IP e o amortecimento). Sempre que houver voltage drop / equalização, dê um parecer técnico relacionando o desnível com a contagem de ciclos e recomende equalização em bancada quando pertinente.

NÃO invente defeitos que não foram informados. Use apenas os dados fornecidos. Se drone e carregador foram testados e estão OK, mencione na seção 1.

ITENS OBRIGATÓRIOS em TODAS as análises, independentemente dos defeitos encontrados:
- Seção 2 DEVE sempre conter um parágrafo sobre a saúde química das células: desgaste eletroquímico, capacidade residual, sincronia entre células e nível de envelhecimento, mesmo que as tensões estejam dentro do limite.
- Seção 6 DEVE sempre conter: (a) status do selo de umidade e consequência para a garantia de fábrica; (b) aviso sobre risco de infiltração; (c) aviso de que podem ocorrer falhas secundárias após a manutenção.

=========================
ESTRUTURA OBRIGATÓRIA (siga este formato):
=========================

LAUDO TÉCNICO DE DIAGNÓSTICO E ANÁLISE - BATERIA DJI AGRAS
Equipamento: Bateria Inteligente de Voo DJI Agras {model_name}
Data da Análise: {data_hoje}
Status: Aguardando Aprovação de Orçamento

1. Verificação de Equipamentos Associados (Testes Iniciais):
[Resultado do teste com Drone e Carregador, se informados]

2. Diagnóstico Eletrônico e Químico:
[Contagem de ciclos, voltage drop/equalização, e Parecer Técnico explicando a química/sincronia das células. OBRIGATÓRIO: incluir sempre um parágrafo sobre a saúde química das células — desgaste eletroquímico das placas de lítio, capacidade residual estimada, grau de envelhecimento e sincronia eletroquímica entre células, explicando as implicações para a performance e segurança em voo.]

3. Diagnóstico Físico e Estrutural:
[Painel de controle/adesivos, vedação/borrachas, danos físicos — cada um com sua consequência]

4. Proposta de Serviço (Plano de Intervenção Corretiva e Preventiva):
[Lista das intervenções recomendadas para corrigir cada item encontrado]

5. Protocolo de Testes:
[Texto sobre testes de bancada/estresse e voo após os serviços, e ressalva de possível nova análise se houver fadiga das células]

6. Garantia e Avisos Importantes:
[SEMPRE incluir os três itens abaixo, mesmo que a bateria não apresente defeitos graves:]
[a) Selo de Umidade: informar se o selo foi ativado (cor alterada). Se ativado, deixar claro que: (1) a garantia de fábrica DJI é automaticamente anulada, pois indica exposição a umidade ou condensação — condição excluída da cobertura do fabricante; (2) a umidade pode ter comprometido internamente as células lítio-polímero de forma não visível na inspeção, portanto o Laboratório BioDron NÃO PODE GARANTIR a saúde das células nem o desempenho pleno após a manutenção; (3) existe risco de degradação acelerada, perda de capacidade ou falha das células mesmo após os serviços realizados, e o cliente está ciente desse risco ao aprovar o orçamento.]
[b) Risco de Infiltração: alertar que qualquer comprometimento da vedação (borrachas, encaixes, adesivos) expõe o BMS e as células lítio-polímero a umidade e agentes químicos do campo (herbicidas, inseticidas), podendo causar corrosão interna, curto-circuito e risco de incêndio.]
[c) Falhas Secundárias: esclarecer que em baterias com desgaste avançado ou que sofreram impacto/infiltração, após a intervenção técnica podem se manifestar falhas secundárias em componentes internos que já estavam comprometidos antes da manutenção — situação inerente ao estado prévio do equipamento e sem responsabilidade do Laboratório BioDron.]

Lembramos sempre que o orçamento detalhado encontra-se em anexo no e-mail ou enviado pelo WhatsApp.

Assinado: Laboratório BioDron - Soluções Tecnológicas

=========================
DADOS REAIS DESTA BATERIA (use estes):
=========================
MODELO: {model_name}

DADOS GERAIS:
{info_txt}

ACHADOS DA INSPEÇÃO (checklist):
{achados_txt}{cell_txt}

=========================
Escreva o laudo completo seguindo a estrutura acima, em texto puro (sem markdown, sem asteriscos, sem ##), pronto para copiar e colar no Omie/proposta. Mantенha os títulos das seções numeradas."""

    def _build_body(modelo):
        gen_config = {"temperature": 0.5, "maxOutputTokens": 4096}
        # thinkingConfig só existe nos modelos 2.5 — desliga o "thinking" que trunca o texto
        if '2.5' in modelo:
            gen_config["thinkingConfig"] = {"thinkingBudget": 0}
        return json.dumps({
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": gen_config
        }).encode('utf-8')

    # Tenta vários modelos em ordem (free tier pode variar por conta)
    env_model = os.environ.get('GEMINI_MODEL')
    modelos = [env_model] if env_model else ['gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-flash-latest', 'gemini-2.5-flash-lite']
    ultimo_erro = ''
    for modelo in modelos:
        if not modelo:
            continue
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{modelo}:generateContent?key={api_key}"
        req = urlreq.Request(url, data=_build_body(modelo), headers={'Content-Type': 'application/json'})
        try:
            with urlreq.urlopen(req, timeout=40) as resp:
                raw = resp.read().decode('utf-8')
            data = json.loads(raw)
            texto = data['candidates'][0]['content']['parts'][0]['text'].strip()
            return jsonify({"success": True, "texto": texto, "modelo": modelo})
        except HTTPError as e:
            try:
                errbody = e.read().decode('utf-8')
            except Exception:
                errbody = str(e)
            ultimo_erro = f"HTTP {e.code} ({modelo}): {errbody[:200]}"
            # 429 (quota), 404 (modelo), 503/500 (sobrecarga) → tenta o próximo modelo
            if e.code in (429, 404, 503, 500):
                continue
            return jsonify({"error": f"Gemini {ultimo_erro}"}), 502
        except (KeyError, IndexError):
            ultimo_erro = f"Resposta sem texto ({modelo}) — pode ter sido bloqueada por segurança."
            continue
        except URLError as e:
            return jsonify({"error": f"Falha de conexão com Gemini: {e.reason}"}), 502

    return jsonify({"error": f"Gemini: todos os modelos falharam. Último erro: {ultimo_erro}"}), 502


def _gerar_pdf_laudo(payload):
    """Gera PDF do laudo a partir do payload do frontend usando ReportLab."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
    from reportlab.lib.utils import ImageReader

    # Paleta da marca
    C_PRIMARY = colors.HexColor('#1e40af')   # azul Biodron
    C_DARK = colors.HexColor('#1e293b')      # slate escuro
    C_LIGHT = colors.HexColor('#f1f5f9')     # cinza claro (zebra)
    C_BORDER = colors.HexColor('#d1d5db')
    C_MUTED = colors.HexColor('#6b7280')
    C_OK = colors.HexColor('#16a34a')
    C_BAD = colors.HexColor('#dc2626')

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15*mm, rightMargin=15*mm, topMargin=16*mm, bottomMargin=16*mm, title="Laudo Técnico - Biodron")
    story = []
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle('h1', parent=styles['Heading1'], fontSize=15, spaceAfter=2, textColor=C_DARK)
    h2 = ParagraphStyle('h2', parent=styles['Heading2'], fontSize=11, spaceBefore=4, spaceAfter=8, textColor=colors.white, fontName='Helvetica-Bold', leading=14)
    body = ParagraphStyle('body', parent=styles['BodyText'], fontSize=9, leading=12, textColor=C_DARK)
    small = ParagraphStyle('small', parent=body, fontSize=8, textColor=C_MUTED)

    def secao(titulo):
        """Título de seção em barra colorida (full-width)."""
        tbl = Table([[Paragraph(titulo.upper(), h2)]], colWidths=[180*mm])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), C_PRIMARY),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        return tbl

    # Rodapé com numeração de página + marca
    def _on_page(canvas, doc_):
        canvas.saveState()
        canvas.setStrokeColor(C_BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(15*mm, 12*mm, 195*mm, 12*mm)
        canvas.setFont('Helvetica', 7)
        canvas.setFillColor(C_MUTED)
        canvas.drawString(15*mm, 8*mm, "Laboratório BioDron · Soluções Tecnológicas")
        canvas.drawRightString(195*mm, 8*mm, f"Página {doc_.page}")
        canvas.restoreState()

    header_config = payload.get('headerConfig', [])
    header_data = payload.get('headerData', {})
    answers = payload.get('answers', {})
    questions = payload.get('questions', [])
    diagrams = payload.get('diagrams', [])
    diagram_marks = payload.get('diagramMarks', {})
    report_images = payload.get('reportImages', [])
    logo = payload.get('logo')
    technician = payload.get('technician', '')
    technician_signature = payload.get('technicianSignature')
    show_signatures = payload.get('showSignatures', True)
    model_name = payload.get('modelName', '')

    def _img_from_data_uri(uri, max_w=None, max_h=None):
        """Cria Image do reportlab a partir de data URI."""
        try:
            if not uri or 'base64,' not in uri:
                return None
            b = base64.b64decode(uri.split(',', 1)[1])
            img = ImageReader(io.BytesIO(b))
            iw, ih = img.getSize()
            ratio = iw / ih if ih else 1
            if max_w and iw > max_w:
                iw, ih = max_w, max_w / ratio
            if max_h and ih > max_h:
                iw, ih = max_h * ratio, max_h
            return Image(io.BytesIO(b), width=iw, height=ih)
        except Exception:
            return None

    # ---- Cabeçalho ----
    date_str = ''
    if header_data.get('date'):
        try:
            from datetime import datetime as dt
            d = dt.strptime(header_data['date'], '%Y-%m-%d')
            date_str = d.strftime('%d/%m/%Y')
        except Exception:
            date_str = header_data.get('date', '')

    left_cell = None
    if logo:
        left_cell = _img_from_data_uri(logo, max_w=130, max_h=55)
    if not left_cell:
        left_cell = Paragraph('<b>BioDron</b>', h1)

    right_text = (f"<b><font size=15 color='#1e293b'>RELATÓRIO DE INSPEÇÃO</font></b><br/>"
                  f"<font size=8 color='#6b7280'>Ref.: {model_name or '-'}<br/>"
                  f"Data: {date_str or '-'} &nbsp;|&nbsp; Téc.: {technician or '-'}</font>")
    header_row = [left_cell, Paragraph(right_text, ParagraphStyle('hr', parent=body, alignment=2))]

    t = Table([header_row], colWidths=[75*mm, 105*mm])
    t.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ALIGN', (1,0), (1,0), 'RIGHT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t)
    # Linha colorida sob o cabeçalho
    rule = Table([['']], colWidths=[180*mm], rowHeights=[2])
    rule.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,-1), C_PRIMARY)]))
    story.append(rule)
    story.append(Spacer(1, 5*mm))

    # ---- Informações Gerais ----
    story.append(secao('Informações Gerais'))
    story.append(Spacer(1, 2*mm))
    info_rows = []
    for f in header_config:
        label = f.get('label', '')
        val = header_data.get(f.get('id', ''), '') or '-'
        info_rows.append([Paragraph(f"<b>{label}</b>", body), Paragraph(str(val).replace('\n', '<br/>'), body)])
    if info_rows:
        info_table = Table(info_rows, colWidths=[55*mm, 125*mm])
        info_style = [
            ('LINEBELOW', (0,0), (-1,-1), 0.4, C_BORDER),
            ('BACKGROUND', (0,0), (0,-1), C_LIGHT),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
        ]
        info_table.setStyle(TableStyle(info_style))
        story.append(info_table)
    story.append(Spacer(1, 5*mm))

    def _esc(s):
        return (str(s) if s is not None else '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('\n', '<br/>')

    # ---- Checklist ----
    if questions:
        story.append(secao('Resultados da Inspeção Física'))
        story.append(Spacer(1, 2*mm))
        item_label = ParagraphStyle('item_label', parent=body, fontSize=9.5, leading=12, spaceAfter=1, fontName='Helvetica-Bold')
        item_status_ok = ParagraphStyle('item_ok', parent=body, fontSize=8.5, leading=11, leftIndent=14, textColor=C_MUTED, spaceAfter=7)
        item_status_anormal = ParagraphStyle('item_anormal', parent=body, fontSize=9, leading=12, leftIndent=14, textColor=C_DARK, spaceAfter=7)

        for q in questions:
            ans = answers.get(q.get('id'), {}) or {}
            checked = ans.get('checked')
            qtype = q.get('type', 'checkbox')
            anormal = False
            if qtype == 'text':
                status = ans.get('text') or '-'
                anormal = bool(ans.get('text'))
            elif checked:
                anormal = True
                if qtype == 'checkbox_qty':
                    status = f"{ans.get('qty', '-')} unid."
                elif qtype == 'checkbox_text':
                    status = ans.get('text') or 'Constatado'
                else:
                    status = 'Constatado'
            else:
                status = 'Não Constatado'

            # Marcador colorido: vermelho pra anormal, verde pra ok
            cor = '#dc2626' if anormal else '#16a34a'
            marker = '&#8226;'  # bullet (WinAnsi-safe); cor indica anormal/ok
            story.append(Paragraph(f'<font color="{cor}">{marker}</font> {_esc(q.get("label",""))}', item_label))
            style = item_status_anormal if anormal else item_status_ok
            story.append(Paragraph(_esc(status), style))
        story.append(Spacer(1, 5*mm))

    # ---- Análise de Células ----
    cell_analysis = payload.get('cellAnalysis')  # { enabled, numCells, maxDropV }
    cell_voltages_list = payload.get('cellVoltagesList') or []  # array de strings
    if cell_analysis and cell_analysis.get('enabled') and cell_voltages_list:
        try:
            num_cells = int(cell_analysis.get('numCells') or 14)
            max_drop = float(cell_analysis.get('maxDropV') or 0.2)
            vals = []
            for v in cell_voltages_list:
                try:
                    fv = float(v)
                    if fv > 0:
                        vals.append(fv)
                except Exception:
                    pass
            if vals:
                total = sum(vals)
                avg = total / len(vals)
                vmax = max(vals)
                vmin = min(vals)
                drop = vmax - vmin
                ratio = (drop / max_drop) if max_drop > 0 else 0
                if drop == 0 or ratio <= 0.25:
                    bal_label, bal_hex = 'Balanceada', '#10b981'
                elif ratio <= 0.5:
                    bal_label, bal_hex = 'Levemente Desbalanceada', '#eab308'
                elif ratio <= 0.75:
                    bal_label, bal_hex = 'Quase no Limite', '#f97316'
                elif ratio <= 1.0:
                    bal_label, bal_hex = 'No Limite', '#ef4444'
                else:
                    bal_label, bal_hex = 'Totalmente Desbalanceada', '#991b1b'

                story.append(PageBreak())
                story.append(secao('Análise de Células'))
                story.append(Spacer(1, 3*mm))

                # Cartão de Resumo (com zebra) + Cartão de Status grande lado a lado
                resumo_pairs = [
                    ('Células avaliadas', f"{len(vals)} de {num_cells}"),
                    ('Tensão total', f"{total:.3f} V"),
                    ('Tensão média', f"{avg:.3f} V"),
                    ('Tensão máxima', f"{vmax:.3f} V"),
                    ('Tensão mínima', f"{vmin:.3f} V"),
                    ('Voltage Drop', f"{drop:.3f} V"),
                    ('Limite configurado', f"{max_drop:.3f} V"),
                ]
                resumo_rows = [[Paragraph(f'<b>{k}</b>', small), Paragraph(f'<font name="Helvetica-Bold">{v}</font>', body)] for k, v in resumo_pairs]
                resumo_table = Table(resumo_rows, colWidths=[45*mm, 40*mm])
                rstyle = [
                    ('LINEBELOW', (0,0), (-1,-1), 0.3, C_BORDER),
                    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                    ('TOPPADDING', (0,0), (-1,-1), 4),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                    ('LEFTPADDING', (0,0), (-1,-1), 6),
                ]
                for ri in range(len(resumo_rows)):
                    if ri % 2 == 1:
                        rstyle.append(('BACKGROUND', (0,ri), (-1,ri), C_LIGHT))
                resumo_table.setStyle(TableStyle(rstyle))

                status_card = Table([
                    [Paragraph('<font color="#6b7280" size=8>STATUS DE BALANCEAMENTO</font>', small)],
                    [Paragraph(f'<b><font color="{bal_hex}" size=15>{bal_label}</font></b>', body)],
                    [Paragraph(f'<font color="#6b7280" size=8>Voltage drop {drop:.3f}V (limite {max_drop:.3f}V)</font>', small)],
                ], colWidths=[80*mm])
                status_card.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,-1), C_LIGHT),
                    ('BOX', (0,0), (-1,-1), 1.2, colors.HexColor(bal_hex)),
                    ('TOPPADDING', (0,0), (-1,-1), 6),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                    ('LEFTPADDING', (0,0), (-1,-1), 12),
                ]))

                combo = Table([[resumo_table, status_card]], colWidths=[90*mm, 90*mm])
                combo.setStyle(TableStyle([('VALIGN', (0,0), (-1,-1), 'TOP')]))
                story.append(combo)
                story.append(Spacer(1, 5*mm))

                # Tabela de células com zebra + status colorido
                rows = [['Célula', 'Tensão (V)', 'Desvio Médio', 'Status']]
                row_colors = []
                for i in range(num_cells):
                    raw = cell_voltages_list[i] if i < len(cell_voltages_list) else ''
                    try:
                        v = float(raw)
                    except Exception:
                        v = None
                    if v is None or v <= 0:
                        rows.append([str(i+1), '—', '—', '—'])
                        row_colors.append(None)
                    else:
                        dev = v - avg
                        is_max = v == vmax and len(vals) > 1
                        is_min = v == vmin and len(vals) > 1
                        status_txt = 'Maior' if is_max else ('Menor' if is_min else 'Normal')
                        dev_str = f"{'+' if dev >= 0 else ''}{dev:.3f}"
                        rows.append([str(i+1), f"{v:.3f}", dev_str, status_txt])
                        row_colors.append('#1d4ed8' if is_max else ('#c2410c' if is_min else None))
                cells_table = Table(rows, colWidths=[22*mm, 38*mm, 38*mm, 38*mm], repeatRows=1)
                cstyle = [
                    ('BACKGROUND', (0,0), (-1,0), C_DARK),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                    ('FONTSIZE', (0,0), (-1,-1), 9),
                    ('TOPPADDING', (0,0), (-1,-1), 4),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                    ('LINEBELOW', (0,0), (-1,-1), 0.3, C_BORDER),
                ]
                for ri in range(1, len(rows)):
                    if ri % 2 == 0:
                        cstyle.append(('BACKGROUND', (0,ri), (-1,ri), C_LIGHT))
                    rc = row_colors[ri-1]
                    if rc:
                        cstyle.append(('TEXTCOLOR', (3,ri), (3,ri), colors.HexColor(rc)))
                        cstyle.append(('FONTNAME', (3,ri), (3,ri), 'Helvetica-Bold'))
                cells_table.setStyle(TableStyle(cstyle))
                story.append(cells_table)
                story.append(Spacer(1, 4*mm))
        except Exception as e:
            print(f"[CELL ANALYSIS] erro ao gerar: {e}", flush=True)

    # ---- Diagramas com marcações ----
    if diagrams:
        story.append(secao('Mapeamento Visual'))
        story.append(Spacer(1, 2*mm))
        legenda_x = ParagraphStyle('legenda_x', parent=body, fontSize=9, textColor=C_BAD, spaceAfter=4)
        story.append(Paragraph('<b><font color="#dc2626">X</font></b> &nbsp; As marcações em vermelho indicam áreas com amassados, trincados ou danos físicos severos.', legenda_x))
        story.append(Spacer(1, 2*mm))
        diag_imgs = []
        for d in diagrams:
            base = d.get('imageBase64')
            if not base:
                continue
            try:
                img_data = base64.b64decode(base.split(',', 1)[1] if ',' in base else base)
                from PIL import Image as PILImage, ImageDraw, ImageFont
            except Exception:
                # Sem Pillow, só insere a imagem sem marcações
                img = _img_from_data_uri(base, max_w=85*mm, max_h=80*mm)
                if img:
                    diag_imgs.append([Paragraph(f"<b>{d.get('name','')}</b>", small), img])
                continue
            # Com Pillow: desenha as marcações em cima
            try:
                pil = PILImage.open(io.BytesIO(img_data)).convert('RGB')
                draw = ImageDraw.Draw(pil)
                marks = diagram_marks.get(d.get('id'), [])
                w, h = pil.size
                for m in marks:
                    x = int(m.get('x', 0) / 100 * w)
                    y = int(m.get('y', 0) / 100 * h)
                    size = max(20, w // 30)
                    draw.line([(x-size,y-size),(x+size,y+size)], fill='red', width=max(3, w//200))
                    draw.line([(x-size,y+size),(x+size,y-size)], fill='red', width=max(3, w//200))
                out_buf = io.BytesIO()
                pil.save(out_buf, 'PNG')
                out_buf.seek(0)
                img = Image(out_buf, width=80*mm, height=70*mm, kind='proportional')
                diag_imgs.append([Paragraph(f"<b>{d.get('name','')}</b>", small), img])
            except Exception:
                pass
        # 2 colunas de diagramas
        rows = []
        for i in range(0, len(diag_imgs), 2):
            chunk = diag_imgs[i:i+2]
            if len(chunk) == 1:
                chunk.append(['', ''])
            row = []
            for cell in chunk:
                inner = Table([[cell[0]], [cell[1]]], colWidths=[85*mm])
                inner.setStyle(TableStyle([('ALIGN', (0,0), (-1,-1), 'CENTER')]))
                row.append(inner)
            rows.append(row)
        if rows:
            outer = Table(rows, colWidths=[90*mm, 90*mm])
            outer.setStyle(TableStyle([('VALIGN', (0,0), (-1,-1), 'TOP'), ('PADDING', (0,0), (-1,-1), 4)]))
            story.append(outer)
        story.append(Spacer(1, 4*mm))

    # ---- Fotos ----
    if report_images:
        story.append(PageBreak())
        story.append(secao('Evidências Fotográficas'))
        story.append(Spacer(1, 2*mm))
        photo_rows = []
        row = []
        for idx, img_info in enumerate(report_images):
            src = img_info.get('src', '')
            cap = img_info.get('caption') or 'Sem legenda'
            img = _img_from_data_uri(src, max_w=80*mm, max_h=70*mm)
            if not img:
                continue
            cell = Table([[img], [Paragraph(f'<b>{_esc(cap)}</b>', small)]], colWidths=[85*mm])
            cell.setStyle(TableStyle([
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('BOX', (0,0), (0,0), 0.5, C_BORDER),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ]))
            row.append(cell)
            if len(row) == 2:
                photo_rows.append(row); row = []
        if row:
            if len(row) == 1: row.append('')
            photo_rows.append(row)
        if photo_rows:
            t = Table(photo_rows, colWidths=[90*mm, 90*mm])
            t.setStyle(TableStyle([('VALIGN', (0,0), (-1,-1), 'TOP'), ('PADDING', (0,0), (-1,-1), 4)]))
            story.append(t)

    # ---- Assinatura do Técnico (somente) ----
    if show_signatures:
        story.append(Spacer(1, 15*mm))
        rows = []
        if technician_signature:
            sig_img = _img_from_data_uri(technician_signature, max_w=60*mm, max_h=20*mm)
            if sig_img:
                rows.append([sig_img])
        rows.append([Paragraph('_________________________<br/><b>Técnico Responsável</b>', body)])
        sig_table = Table(rows, colWidths=[90*mm])
        sig_table.setStyle(TableStyle([
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'BOTTOM'),
        ]))
        story.append(sig_table)

    # ---- Página de OS / Orçamento (serviços + peças com valores) ----
    osq = payload.get('osQuote') or {}
    q_services = osq.get('services') or []
    q_parts = osq.get('parts') or []
    if q_services or q_parts:
        def _brl(v):
            try:
                v = float(v or 0)
            except Exception:
                v = 0.0
            return "R$ " + f"{v:,.2f}".replace(',', 'X').replace('.', ',').replace('X', '.')

        def _fmt_qty(q):
            try:
                q = float(q or 0)
            except Exception:
                q = 0.0
            return str(int(q)) if q.is_integer() else f"{q:.2f}".replace('.', ',')

        th = ParagraphStyle('th', parent=body, textColor=colors.white, fontName='Helvetica-Bold')
        th_c = ParagraphStyle('th_c', parent=th, alignment=1)
        th_r = ParagraphStyle('th_r', parent=th, alignment=2)
        cell_c = ParagraphStyle('cell_c', parent=body, alignment=1)
        cell_r = ParagraphStyle('cell_r', parent=body, alignment=2)
        col_widths = [96*mm, 18*mm, 30*mm, 36*mm]

        def _tabela_itens(label, itens):
            data = [[Paragraph(label, th), Paragraph('Qtd', th_c), Paragraph('Valor Unit.', th_r), Paragraph('Total', th_r)]]
            subtotal = 0.0
            for it in itens:
                qty = float(it.get('quantity') or 0)
                unit = float(it.get('unitPrice') or 0)
                tot = qty * unit
                subtotal += tot
                # Descrição curta: corta o laudo embutido (após '||' / '|' / quebra de linha) e limita tamanho.
                desc = str(it.get('description') or it.get('code') or '—')
                desc = desc.split('||')[0].split('\n')[0].split('|')[0].strip() or (it.get('code') or '—')
                if len(desc) > 110:
                    desc = desc[:107] + '...'
                data.append([
                    Paragraph(desc, body),
                    Paragraph(_fmt_qty(qty), cell_c),
                    Paragraph(_brl(unit), cell_r),
                    Paragraph(_brl(tot), cell_r),
                ])
            t = Table(data, colWidths=col_widths, repeatRows=1)
            st = [
                ('BACKGROUND', (0,0), (-1,0), C_PRIMARY),
                ('GRID', (0,0), (-1,-1), 0.4, C_BORDER),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('LEFTPADDING', (0,0), (-1,-1), 5),
                ('RIGHTPADDING', (0,0), (-1,-1), 5),
            ]
            for i in range(2, len(data), 2):
                st.append(('BACKGROUND', (0,i), (-1,i), C_LIGHT))
            t.setStyle(TableStyle(st))
            return t, subtotal

        story.append(PageBreak())
        story.append(secao("Ordem de Serviço / Orçamento"))
        story.append(Spacer(1, 6))

        info_bits = []
        if osq.get('osNumber'):
            info_bits.append(f"<b>OS Nº:</b> {osq.get('osNumber')}")
        if osq.get('clientName'):
            doc_str = f" — {osq.get('clientDoc')}" if osq.get('clientDoc') else ""
            info_bits.append(f"<b>Cliente:</b> {osq.get('clientName')}{doc_str}")
        if osq.get('paymentTerm'):
            info_bits.append(f"<b>Pagamento:</b> {osq.get('paymentTerm')}")
        if osq.get('category'):
            info_bits.append(f"<b>Categoria:</b> {osq.get('category')}")
        if info_bits:
            story.append(Paragraph("<br/>".join(info_bits), body))
            story.append(Spacer(1, 8))

        total_geral = 0.0
        if q_services:
            t, sub = _tabela_itens('Serviços', q_services)
            total_geral += sub
            story.append(t)
            story.append(Spacer(1, 8))
        if q_parts:
            t, sub = _tabela_itens('Peças', q_parts)
            total_geral += sub
            story.append(t)
            story.append(Spacer(1, 8))

        tot_tbl = Table([[Paragraph('<b>TOTAL GERAL</b>', th_r), Paragraph(f"<b>{_brl(total_geral)}</b>", th_r)]],
                        colWidths=[144*mm, 36*mm])
        tot_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), C_DARK),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(tot_tbl)
        story.append(Spacer(1, 6))
        story.append(Paragraph("Documento gerado automaticamente pelo Biodron Smart Report. Valores sujeitos a confirmação.", small))

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    return buf.getvalue()


@app.route('/api/gerar-pdf-download', methods=['POST'])
def gerar_pdf_download():
    """Gera o PDF do laudo (mesmo gerador do anexo Omie) e devolve pra download direto."""
    user, full_data, err = _require_user()
    if err:
        return err
    payload = request.json or {}
    try:
        pdf_bytes = _gerar_pdf_laudo(payload)
    except Exception as e:
        return jsonify({"error": f"Falha ao gerar PDF: {e}"}), 500
    filename = payload.get('filename') or 'laudo.pdf'
    return Response(pdf_bytes, mimetype='application/pdf',
                    headers={'Content-Disposition': f'attachment; filename="{filename}"'})


@app.route('/api/os/<os_id>/gerar-pdf-anexar', methods=['POST'])
def os_gerar_pdf_anexar(os_id):
    """Gera o PDF do laudo no servidor e anexa direto na OS do Omie (funciona em mobile)."""
    user, full_data, err = _require_user()
    if err:
        return err
    owner, draft = _find_filial_draft(full_data, user, os_id)
    if not draft:
        return jsonify({"error": "Rascunho não encontrado"}), 404
    if not draft.get('omieOsId'):
        return jsonify({"error": "OS precisa estar enviada/importada do Omie."}), 400

    payload = request.json or {}
    # Injeta os dados da OS (serviços + peças com valores) pra gerar a página de Orçamento no PDF.
    if not payload.get('osQuote'):
        cli = draft.get('client') or {}
        payload['osQuote'] = {
            "osNumber": draft.get('omieOsNumber') or '',
            "clientName": cli.get('name') or '',
            "clientDoc": cli.get('document') or '',
            "services": draft.get('services') or [],
            "parts": draft.get('parts') or [],
            "paymentTerm": "À vista",
            "category": CATEGORIA_PEDIDO_VENDA_PADRAO,
        }
    try:
        pdf_bytes = _gerar_pdf_laudo(payload)
    except Exception as e:
        return jsonify({"error": f"Falha ao gerar PDF: {e}"}), 500

    filename = f"laudo_OS_{draft.get('omieOsNumber') or os_id}.pdf"

    # Zipa e anexa no Omie
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, pdf_bytes)
    zip_content = zip_buf.getvalue()
    zip_b64 = base64.b64encode(zip_content).decode('utf-8')
    md5_hash = hashlib.md5(zip_b64.encode('ascii')).hexdigest()

    cod_int = f"anx_{os_id}_{int(datetime.utcnow().timestamp())}"[:20]
    try:
        omie_call('/geral/anexo/', 'IncluirAnexo', {
            "cCodIntAnexo": cod_int,
            "cTabela": "ordem-servico",
            "nId": draft['omieOsId'],
            "cNomeArquivo": filename,
            "cTipoArquivo": "pdf",
            "cArquivo": zip_b64,
            "cMd5": md5_hash
        })
        draft['pdfAnexado'] = True
        draft['pdfAnexadoAt'] = datetime.utcnow().isoformat() + "Z"
        save_data(full_data)
        return jsonify({"success": True})
    except OmieError as e:
        return jsonify({"error": str(e)}), e.status


@app.route('/api/os/<os_id>/anexar', methods=['POST'])
def os_anexar(os_id):
    """Anexa um PDF (base64) à OS no Omie. PDF é zipado, base64-ado e enviado via IncluirAnexo."""
    user, full_data, err = _require_user()
    if err:
        return err
    owner, draft = _find_filial_draft(full_data, user, os_id)
    if not draft:
        return jsonify({"error": "Rascunho não encontrado"}), 404
    if not draft.get('omieOsId'):
        return jsonify({"error": "OS precisa estar enviada/importada do Omie antes de anexar PDF."}), 400

    body = request.json or {}
    pdf_b64 = body.get('pdf_base64') or ''
    filename = body.get('filename') or f"laudo_{os_id}.pdf"
    # Remove prefixo data: caso venha como data URI
    if ',' in pdf_b64 and pdf_b64.startswith('data:'):
        pdf_b64 = pdf_b64.split(',', 1)[1]
    if not pdf_b64:
        return jsonify({"error": "PDF não fornecido"}), 400

    try:
        pdf_bytes = base64.b64decode(pdf_b64)
    except Exception:
        return jsonify({"error": "PDF base64 inválido"}), 400

    # Zipa o PDF (Omie exige zip + base64)
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, pdf_bytes)
    zip_content = zip_buf.getvalue()
    zip_b64 = base64.b64encode(zip_content).decode('utf-8')
    # Omie espera MD5 da STRING base64 (não dos bytes binários do zip)
    md5_hash = hashlib.md5(zip_b64.encode('ascii')).hexdigest()
    print(f"[ANEXAR-PDF] zip_size={len(zip_content)} b64_size={len(zip_b64)} md5={md5_hash}", flush=True)

    cod_int = f"anx_{os_id}_{int(datetime.utcnow().timestamp())}"[:20]

    try:
        omie_call('/geral/anexo/', 'IncluirAnexo', {
            "cCodIntAnexo": cod_int,
            "cTabela": "ordem-servico",
            "nId": draft['omieOsId'],
            "cNomeArquivo": filename,
            "cTipoArquivo": "pdf",
            "cArquivo": zip_b64,
            "cMd5": md5_hash
        })
        draft['pdfAnexado'] = True
        draft['pdfAnexadoAt'] = datetime.utcnow().isoformat() + "Z"
        save_data(full_data)
        return jsonify({"success": True})
    except OmieError as e:
        return jsonify({"error": str(e)}), e.status


@app.route('/api/os/<os_id>/anexar-fotos', methods=['POST'])
def os_anexar_fotos(os_id):
    """Recebe um array de imagens base64 (data URI) e anexa como ZIP único à OS Omie."""
    user, full_data, err = _require_user()
    if err:
        return err
    owner, draft = _find_filial_draft(full_data, user, os_id)
    if not draft:
        return jsonify({"error": "Rascunho não encontrado"}), 404
    if not draft.get('omieOsId'):
        return jsonify({"error": "OS precisa estar enviada/sincronizada ao Omie antes de anexar fotos."}), 400

    body = request.json or {}
    fotos = body.get('photos') or []
    if not fotos:
        return jsonify({"error": "Nenhuma foto fornecida"}), 400
    fotos_count = len(fotos)

    # Cria ZIP com todas as fotos. Libera cada foto da memória logo após zipar (poupa RAM no plano 512MB).
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for idx in range(1, len(fotos) + 1):
            foto = fotos[idx - 1]
            src = foto.get('src') or ''
            caption = (foto.get('caption') or f'foto_{idx}').strip()
            # Sanitiza nome de arquivo
            safe_name = re.sub(r'[^a-zA-Z0-9_.\- ]', '_', caption)[:60] or f'foto_{idx}'
            # Extrai extensão do data URI
            ext = 'jpg'
            if 'image/png' in src:
                ext = 'png'
            elif 'image/webp' in src:
                ext = 'webp'
            # Pega só a parte base64
            if ',' in src:
                src = src.split(',', 1)[1]
            try:
                img_bytes = base64.b64decode(src)
                zf.writestr(f"{idx:02d}_{safe_name}.{ext}", img_bytes)
            except Exception:
                pass
            # Libera a foto já processada
            fotos[idx - 1] = None
            src = None
    fotos = None  # libera a lista inteira

    zip_content = zip_buf.getvalue()
    zip_buf = None
    if not zip_content:
        return jsonify({"error": "Falha ao gerar ZIP"}), 500

    # Pra anexo Omie, o conteúdo precisa ser zip + base64.
    # Como já é um zip, faz outro envelope zip que contém o zip de fotos.
    outer = io.BytesIO()
    filename = f"fotos_OS_{draft.get('omieOsNumber') or os_id}.zip"
    with zipfile.ZipFile(outer, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, zip_content)
    zip_content = None
    outer_bytes = outer.getvalue()
    outer = None
    outer_b64 = base64.b64encode(outer_bytes).decode('utf-8')
    outer_bytes = None
    # Omie espera MD5 da STRING base64 (não dos bytes binários)
    md5_hash = hashlib.md5(outer_b64.encode('ascii')).hexdigest()
    print(f"[ANEXAR-FOTOS] b64_size={len(outer_b64)} md5={md5_hash}", flush=True)

    cod_int = f"fts_{os_id}_{int(datetime.utcnow().timestamp())}"[:20]
    try:
        omie_call('/geral/anexo/', 'IncluirAnexo', {
            "cCodIntAnexo": cod_int,
            "cTabela": "ordem-servico",
            "nId": draft['omieOsId'],
            "cNomeArquivo": filename,
            "cTipoArquivo": "zip",
            "cArquivo": outer_b64,
            "cMd5": md5_hash
        })
        draft['fotosAnexadas'] = True
        draft['fotosAnexadasAt'] = datetime.utcnow().isoformat() + "Z"
        draft['fotosCount'] = fotos_count
        save_data(full_data)
        return jsonify({"success": True, "count": fotos_count})
    except OmieError as e:
        return jsonify({"error": str(e)}), e.status


def _criar_ou_atualizar_pedido_venda(draft, parts_validas, nCodCC):
    """Cria (ou atualiza, se já existir) um Pedido de Venda no Omie com as peças + preços.
    Pagamento à vista, mesma categoria do Orçamento. Atualiza draft['pedidoVendaId/Numero'].
    Lança OmieError em caso de falha."""
    # Agrupa peças por produto (soma qtd, mantém maior preço informado)
    agrup = {}
    ordem = []
    for p in parts_validas:
        cod = int(p.get('omieProductId') or 0)
        if cod == 0:
            continue
        if cod not in agrup:
            agrup[cod] = {"quantidade": 0.0, "valor_unitario": 0.0}
            ordem.append(cod)
        agrup[cod]["quantidade"] += float(p.get('quantity') or 1)
        pu = float(p.get('unitPrice') or 0)
        if pu > agrup[cod]["valor_unitario"]:
            agrup[cod]["valor_unitario"] = pu
    if not ordem:
        return

    cli = draft.get('client') or {}
    categ_pv = get_categoria_pedido_venda_code()
    det = []
    for cod in ordem:
        info = agrup[cod]
        det.append({
            "ide": {"codigo_item_integracao": f"{draft['id']}-{cod}"[:60]},
            "produto": {
                "codigo_produto": cod,
                "quantidade": info["quantidade"],
                "valor_unitario": info["valor_unitario"]
            }
        })

    cabecalho = {
        "codigo_cliente": int(cli.get('omieClientId')),
        "codigo_pedido_integracao": f"sr-{draft['id']}"[:60],
        "data_previsao": datetime.utcnow().strftime("%d/%m/%Y"),
        "etapa": "10",
        "codigo_parcela": "000",  # à vista
        "quantidade_itens": len(det)
    }
    info_ad = {
        "codigo_conta_corrente": int(nCodCC),
        "consumidor_final": "S",
        "enviar_email": "N"
    }
    if categ_pv:
        info_ad["codigo_categoria"] = categ_pv

    ped_id = draft.get('pedidoVendaId')
    if ped_id:
        cabecalho["codigo_pedido"] = int(ped_id)
        result = omie_call('/produtos/pedido/', 'AlterarPedidoVenda',
                           {"cabecalho": cabecalho, "det": det, "informacoes_adicionais": info_ad})
    else:
        try:
            result = omie_call('/produtos/pedido/', 'IncluirPedido',
                               {"cabecalho": cabecalho, "det": det, "informacoes_adicionais": info_ad})
        except OmieError as e:
            # Já existe um pedido com esse código de integração: consulta e altera
            if 'cadastrad' in str(e).lower():
                cons = omie_call('/produtos/pedido/', 'ConsultarPedido',
                                 {"codigo_pedido_integracao": cabecalho["codigo_pedido_integracao"]})
                nped = ((cons.get('pedido_venda_produto') or {}).get('cabecalho') or {}).get('codigo_pedido')
                if not nped:
                    raise
                cabecalho["codigo_pedido"] = int(nped)
                result = omie_call('/produtos/pedido/', 'AlterarPedidoVenda',
                                   {"cabecalho": cabecalho, "det": det, "informacoes_adicionais": info_ad})
            else:
                raise

    if result.get('codigo_pedido'):
        draft['pedidoVendaId'] = result.get('codigo_pedido')
    if result.get('numero_pedido'):
        draft['pedidoVendaNumero'] = result.get('numero_pedido')


@app.route('/api/os/<os_id>/send', methods=['POST'])
def os_send(os_id):
    user, full_data, err = _require_user()
    if err:
        return err
    owner, draft = _find_filial_draft(full_data, user, os_id)
    if not draft:
        return jsonify({"error": "Rascunho não encontrado"}), 404

    # Determina se é UPDATE (já existe no Omie) ou CREATE (rascunho novo)
    is_update = bool(draft.get('omieOsId'))

    # Só bloqueia "já enviado" pra rascunhos novos (não pra OSes importadas do Omie)
    if not is_update and draft.get('status') == 'sent':
        return jsonify({"error": "OS já foi enviada anteriormente"}), 400

    cli = draft.get('client') or {}
    if not cli.get('omieClientId'):
        return jsonify({"error": "Selecione (ou cadastre) o cliente no Omie antes de enviar."}), 400

    # Valida que todas as peças têm vínculo Omie
    for p in draft.get('parts', []):
        if not p.get('omieProductId'):
            return jsonify({"error": f"Peça '{p.get('description','')}' não está vinculada ao catálogo Omie."}), 400

    # Observações puras (sem mais "Peças utilizadas:" embutido — agora vão pro produtosUtilizados)
    obs_combinada = (draft.get('observations') or '').strip()

    itens = []
    for idx, s in enumerate(draft.get('services', [])):
        sid = s.get('omieServiceId')
        # nCodServico = 0 é válido na Omie (serviço genérico, só descrição). None/null não é.
        if sid is None:
            return jsonify({"error": f"Serviço '{s.get('description','')}' não está vinculado ao catálogo Omie."}), 400
        qty = float(s.get('quantity') or 1)
        price = float(s.get('unitPrice') or 0)
        desc = s.get('description') or ''
        # No primeiro serviço, anexa observações como parte da descrição detalhada do serviço
        if idx == 0 and obs_combinada:
            desc = (desc + "\n\n" + obs_combinada).strip()
        item = {
            "nSeqItem": idx + 1,
            "nCodServico": int(sid),
            "cDescServ": desc,
            "nQtde": qty,
            "nValUnit": price,
            "cTribServ": s.get('cTribServ') or '01',
            "cCodServMun": s.get('cCodServMun') or '',
            "cCodServLC116": s.get('cCodLC116') or ''
        }
        # Preserva nIdItem original se o item veio da OS importada (Omie pode exigir)
        if s.get('nIdItem'):
            item["nIdItem"] = int(s['nIdItem'])
        itens.append(item)

    # Pega cCodCateg do primeiro serviço (todos da OS compartilham essa categoria)
    primeiro_servico = draft.get('services', [{}])[0]
    cod_categ = primeiro_servico.get('cCodCateg') or '1.01.02'

    # Pega Conta Corrente ATIVA do Omie (em cache). Prioriza tipo CC sobre CX/Cartao.
    nCodCC = _cache_get('default_cc')
    if nCodCC is None:
        try:
            cc_data = omie_call('/geral/contacorrente/', 'ListarContasCorrentes', {
                "pagina": 1,
                "registros_por_pagina": 50,
                "apenas_importado_api": "N"
            })
            contas = cc_data.get('ListarContasCorrentes') or []
            # Filtra apenas ativas
            ativas = [c for c in contas if (c.get('inativo') or 'N').upper() != 'S']
            # Prefere tipo CC (Conta Corrente) sobre CX (Caixa) e outros
            preferidas = [c for c in ativas if (c.get('tipo') or '').upper() == 'CC']
            escolhida = (preferidas[0] if preferidas else (ativas[0] if ativas else None))
            if escolhida:
                nCodCC = escolhida.get('nCodCC')
                _cache_set('default_cc', nCodCC)
        except OmieError as e:
            return jsonify({"error": f"Não foi possível obter Conta Corrente padrão do Omie: {e}"}), e.status
    if not nCodCC:
        return jsonify({"error": "Nenhuma Conta Corrente ativa encontrada no Omie. Verifique o cadastro."}), 400

    cabecalho = {
        "nCodCli": cli['omieClientId'],
        "cCodParc": "000",
        "nQtdeParc": 1,
        "dDtPrevisao": datetime.utcnow().strftime("%d/%m/%Y"),
        "cEtapa": "10"
    }
    if is_update:
        # Pra AlterarOS, manda nCodOS dentro do Cabecalho (identifica a OS no Omie)
        cabecalho["nCodOS"] = int(draft['omieOsId'])
        # Preserva cCodIntOS original (consulta no Omie se ainda não tem cacheado)
        cci_orig = draft.get('cCodIntOSOriginal')
        if cci_orig is None:
            try:
                consulta = omie_call('/servicos/os/', 'ConsultarOS', {"nCodOS": int(draft['omieOsId'])})
                cci_orig = (consulta.get('Cabecalho') or {}).get('cCodIntOS') or ''
                draft['cCodIntOSOriginal'] = cci_orig
            except OmieError:
                cci_orig = ''
        if cci_orig:
            cabecalho["cCodIntOS"] = cci_orig
    else:
        # Pra IncluirOS, manda cCodIntOS como código de integração local
        cabecalho["cCodIntOS"] = draft['id']

    param = {
        "Cabecalho": cabecalho,
        "InformacoesAdicionais": {
            "cCodCateg": draft.get('cCodCategFromOmie') or cod_categ,
            "nCodCC": draft.get('nCodCCFromOmie') or nCodCC,
            "cDadosAdicNF": ""
        },
        "ServicosPrestados": itens
    }

    # Log de debug
    import sys
    print(f"[OS-SEND] is_update={is_update} call={'AlterarOS' if is_update else 'IncluirOS'} servicos={len(itens)}", flush=True)
    sys.stdout.flush()

    # As peças NÃO vão como "produtos utilizados" da OS (a API não aceita preço nelas).
    # Elas vão num Pedido de Venda separado, criado/atualizado logo após o envio da OS.
    parts_validas = [p for p in (draft.get('parts') or []) if p.get('omieProductId')]

    try:
        call_name = 'AlterarOS' if is_update else 'IncluirOS'
        result = omie_call('/servicos/os/', call_name, param)
        draft['status'] = 'sent'
        if not is_update:
            draft['omieOsId'] = result.get('nCodOS')
            draft['omieOsNumber'] = result.get('cNumOS')
        draft['sentAt'] = datetime.utcnow().isoformat() + "Z"
        draft['sendError'] = None
    except OmieError as e:
        draft['sendError'] = str(e)
        save_data(full_data)
        return jsonify({"error": str(e)}), e.status

    # Cria/atualiza o Pedido de Venda das peças (preço + à vista + categoria).
    draft['pedidoVendaError'] = None
    if parts_validas:
        try:
            _criar_ou_atualizar_pedido_venda(draft, parts_validas, draft.get('nCodCCFromOmie') or nCodCC)
        except OmieError as e:
            draft['pedidoVendaError'] = str(e)

    save_data(full_data)
    if draft.get('pedidoVendaError'):
        return jsonify({**draft, "warning": f"OS enviada, mas falhou ao gerar o Pedido de Venda das peças: {draft['pedidoVendaError']}"})
    return jsonify(draft)


HTML_PAGE = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="google" content="notranslate">
    <title>Biodron Smart Report Pro - Baterias</title>

    <!-- PWA (app instalável) -->
    <link rel="manifest" href="/manifest.webmanifest">
    <meta name="theme-color" content="#1e40af">
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="apple-mobile-web-app-title" content="Smart Report">
    <link rel="apple-touch-icon" href="/icon-192.png">
    <link rel="icon" type="image/png" href="/icon-192.png">
    <script>
        if ('serviceWorker' in navigator) {
            window.addEventListener('load', function () {
                navigator.serviceWorker.register('/sw.js').catch(function (e) { console.log('SW falhou', e); });
            });
        }
    </script>

    <script src="https://cdn.tailwindcss.com"></script>
    <script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
    <script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
    <script src="https://unpkg.com/htm@3.1.1/dist/htm.js"></script>
    <script src="https://unpkg.com/@phosphor-icons/web"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>

    <style>
        @media print {
            @page { margin: 0; }
            body {
                background: white;
                -webkit-print-color-adjust: exact;
                padding: 0;
            }
            .print\\:hidden { display: none !important; }
            .print\\:block { display: block !important; }
            .diagram-print-container, .prevent-break {
                page-break-inside: avoid;
                break-inside: avoid;
            }
            table { page-break-inside: auto; width: 100%; }
            tr { page-break-inside: avoid; page-break-after: auto; break-inside: avoid; }
            td, th { page-break-inside: avoid; break-inside: avoid; }
            h1, h2, h3, h4, h5 { page-break-after: avoid; break-after: avoid; }
        }
        .diagram-interactive { cursor: crosshair; }
        html, body { overscroll-behavior: none; }
    </style>
</head>
<body class="bg-slate-100 text-slate-800 antialiased print:bg-white">
    <div id="root"></div>

    <script>
        const { useState, useEffect, useRef } = React;
        const html = htm.bind(React.createElement);

        const App = () => {
            // Autenticação
            const [auth, setAuth] = useState(() => {
                const stored = localStorage.getItem('smartReportAuth');
                return stored ? JSON.parse(stored) : null;
            });

            // Tabs e UX
            const [activeTab, setActiveTab] = useState('report');
            const [isLoaded, setIsLoaded] = useState(false);
            const [isSaving, setIsSaving] = useState(false);
            const [loginError, setLoginError] = useState("");
            const [publicLogo, setPublicLogo] = useState(null);
            const [authMode, setAuthMode] = useState('login'); // 'login' | 'register'
            const [registerMsg, setRegisterMsg] = useState({ type: '', text: '' });
            const [mustChangePwd, setMustChangePwd] = useState(false);
            const [pwdChangeMsg, setPwdChangeMsg] = useState("");
            const [tempPasswordInfo, setTempPasswordInfo] = useState(null); // {username, password}

            // DADOS GLOBAIS (Admin dita as regras)
            const [headerConfig, setHeaderConfig] = useState([]);
            const [models, setModels] = useState([]);
            const [logo, setLogo] = useState(null);

            // DADOS DO USUÁRIO (Cada usuário tem o seu)
            const [headerData, setHeaderData] = useState({});
            const [answers, setAnswers] = useState({});
            const [diagramMarks, setDiagramMarks] = useState({});
            const [reportImages, setReportImages] = useState([]);
            const [pdfMargin, setPdfMargin] = useState('1.5cm');
            const [cellVoltages, setCellVoltages] = useState({}); // { modelId: ["3.85", "3.86", ...] }
            const [laudosList, setLaudosList] = useState([]);
            const [laudosModalOpen, setLaudosModalOpen] = useState(false);
            const [iaModalOpen, setIaModalOpen] = useState(false);
            const [iaTexto, setIaTexto] = useState('');
            const [iaLoading, setIaLoading] = useState(false);

            // Estados UI para Modais e Imagens
            const [sourceModalOpen, setSourceModalOpen] = useState(false);
            const [pendingImages, setPendingImages] = useState([]);
            const cameraInputRef = useRef(null);
            const galleryInputRef = useRef(null);
            const [draggedImgIndex, setDraggedImgIndex] = useState(null);
            const [draggedOverImgIndex, setDraggedOverImgIndex] = useState(null);

            // Estados do Admin
            const [editingModelId, setEditingModelId] = useState(null);
            const [usersList, setUsersList] = useState([]);
            const [filiaisList, setFiliaisList] = useState([]);

            // Estados de Ordens de Serviço (Omie)
            const [osDrafts, setOsDrafts] = useState([]);
            const [currentOs, setCurrentOs] = useState(null);
            const [osFilter, setOsFilter] = useState('todas'); // todas | pendentes | enviadas
            const [omieStatus, setOmieStatus] = useState({ checked: false, ok: false, configured: false, message: '' });
            const [omieAbertas, setOmieAbertas] = useState([]);
            const [loadingAbertas, setLoadingAbertas] = useState(false);
            const [clienteSearch, setClienteSearch] = useState('');
            const [clienteResults, setClienteResults] = useState([]);
            const [showNewClienteModal, setShowNewClienteModal] = useState(false);
            const [servicoSearch, setServicoSearch] = useState({ q: '', forIndex: null });
            const [servicoResults, setServicoResults] = useState([]);
            const [produtoSearch, setProdutoSearch] = useState({ q: '', forIndex: null });
            const [produtoResults, setProdutoResults] = useState([]);
            const [osSendError, setOsSendError] = useState('');
            const [finalizando, setFinalizando] = useState(false);

            useEffect(() => {
                fetch('/api/logo').then(r => r.json()).then(d => { if (d.logo) setPublicLogo(d.logo); }).catch(() => {});
            }, []);

            useEffect(() => {
                const storedPending = localStorage.getItem('smartReportPendingImages');
                if (storedPending) {
                    try {
                        setPendingImages(JSON.parse(storedPending));
                        localStorage.removeItem('smartReportPendingImages');
                    } catch (e) {}
                }
            }, []);

            useEffect(() => {
                if (!auth) return;

                fetch('/api/data', { headers: { 'Authorization': auth.token } })
                    .then(res => {
                        if (res.status === 401) throw new Error("Unauthorized");
                        return res.json();
                    })
                    .then(data => {
                        // Aplica Configurações Globais
                        setHeaderConfig(data.globalConfig.headerConfig || []);
                        const loadedModels = data.globalConfig.models || [];
                        setModels(loadedModels);
                        setLogo(data.globalConfig.logo || null);

                        // Aplica Estado do Laudo (Isolado do Usuário)
                        let userHd = data.userState.headerData || {};
                        if(!userHd.date) userHd.date = new Date().toISOString().split('T')[0];
                        if(userHd.showSignatures === undefined) userHd.showSignatures = true;
                        if(!userHd.selectedTemplateId && loadedModels.length > 0) {
                            userHd.selectedTemplateId = loadedModels[0].id;
                        }

                        setHeaderData(userHd);
                        setAnswers(data.userState.answers || {});
                        setDiagramMarks(data.userState.diagramMarks || {});
                        setReportImages(data.userState.reportImages || []);
                        setPdfMargin(data.userState.pdfMargin || '1.5cm');
                        setCellVoltages(data.userState.cellVoltages || {});

                        if(loadedModels.length > 0) setEditingModelId(loadedModels[0].id);
                        setIsLoaded(true);
                    })
                    .catch(() => handleLogout());
            }, [auth]);

            useEffect(() => {
                if (!isLoaded || !auth) return;
                setIsSaving(true);
                const timer = setTimeout(() => {
                    const payload = {
                        userState: { headerData, answers, diagramMarks, reportImages, pdfMargin, cellVoltages }
                    };

                    // Se for admin, salva as configurações globais também
                    if (auth.role === 'admin') {
                        payload.globalConfig = { headerConfig, models, logo };
                    }

                    fetch('/api/data', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': auth.token
                        },
                        body: JSON.stringify(payload)
                    }).then(res => {
                        if (res.status === 401) handleLogout();
                        setIsSaving(false);
                    });
                }, 1000);
                return () => clearTimeout(timer);
            }, [headerConfig, headerData, models, answers, diagramMarks, logo, reportImages, pdfMargin, cellVoltages, isLoaded, auth]);

            // Salva status temp de fotos antes da câmera abrir
            useEffect(() => {
                if (pendingImages.length > 0) {
                    try { localStorage.setItem('smartReportPendingImages', JSON.stringify(pendingImages)); } catch(e) {}
                } else {
                    localStorage.removeItem('smartReportPendingImages');
                }
            }, [pendingImages]);

            // Histórico de Laudos — fetch precisa estar ANTES de qualquer early return (regras de hooks)
            const fetchLaudos = () => {
                if (!auth) return;
                fetch('/api/laudos', { headers: { 'Authorization': auth.token } })
                    .then(r => r.json()).then(d => { if(Array.isArray(d)) setLaudosList(d); });
            };

            useEffect(() => {
                if (auth && isLoaded) fetchLaudos();
            }, [auth, isLoaded]);

            // Busca lista de usuários quando admin abre a aba "Usuários"
            const fetchUsers = () => {
                fetch('/api/users', { headers: { 'Authorization': auth.token } })
                    .then(r => r.json()).then(data => { if(Array.isArray(data)) setUsersList(data); });
            };

            const fetchFiliais = () => {
                fetch('/api/filiais', { headers: { 'Authorization': auth.token } })
                    .then(r => r.json()).then(data => { if(Array.isArray(data)) setFiliaisList(data); });
            };

            const salvarFilial = (payload) => {
                return fetch('/api/filiais', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': auth.token },
                    body: JSON.stringify(payload)
                }).then(r => r.json()).then(d => {
                    if (d.success) { fetchFiliais(); return true; }
                    alert(d.error || 'Erro ao salvar filial'); return false;
                });
            };

            const excluirFilial = (id) => {
                if (!confirm('Excluir esta filial? Os usuários dela voltam pra Matriz.')) return;
                fetch('/api/filiais', {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json', 'Authorization': auth.token },
                    body: JSON.stringify({ id })
                }).then(r => r.json()).then(() => fetchFiliais());
            };

            const trocarFilialUsuario = (username, filialId) => {
                fetch(`/api/users/${encodeURIComponent(username)}/filial`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': auth.token },
                    body: JSON.stringify({ filialId })
                }).then(r => r.json()).then(d => { if (d.success) fetchUsers(); else alert(d.error || 'Erro'); });
            };

            useEffect(() => {
                if (auth && auth.role === 'admin' && (activeTab === 'users' || activeTab === 'settings')) {
                    fetchUsers();
                    fetchFiliais();
                }
            }, [activeTab, auth]);

            // Carrega rascunhos de OS + status Omie quando entra na aba "os"
            const fetchOsDrafts = () => {
                fetch('/api/os', { headers: { 'Authorization': auth.token } })
                    .then(r => r.json()).then(d => { if(Array.isArray(d)) setOsDrafts(d); });
            };
            const clearOmieCache = () => {
                if (!confirm('Limpar cache Omie? A próxima busca vai puxar tudo de novo do Omie (pode demorar).')) return;
                fetch('/api/omie/cache/clear', {
                    method: 'POST',
                    headers: { 'Authorization': auth.token }
                }).then(r => r.json()).then(() => {
                    alert('Cache limpo! Próxima busca vai puxar dados frescos do Omie.');
                    if (activeTab === 'os') fetchOmieAbertas();
                });
            };

            const checkOmieStatus = () => {
                fetch('/api/omie/status', { headers: { 'Authorization': auth.token } })
                    .then(r => r.json()).then(d => setOmieStatus({ checked: true, ok: !!d.ok, configured: !!d.configured, message: d.message || '' }))
                    .catch(() => setOmieStatus({ checked: true, ok: false, configured: false, message: 'Erro de conexão' }));
            };
            useEffect(() => {
                if (auth && activeTab === 'os') {
                    fetchOsDrafts();
                    if (!omieStatus.checked) checkOmieStatus();
                    if (!currentOs) fetchOmieAbertas();
                }
            }, [activeTab, auth, currentOs]);

            // ---- helpers OS ----
            const createNewOs = (prefill = {}) => {
                fetch('/api/os', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': auth.token },
                    body: JSON.stringify(prefill)
                }).then(r => r.json()).then(d => {
                    if (d && d.id) {
                        setCurrentOs(d);
                        fetchOsDrafts();
                        setActiveTab('os');
                    }
                });
            };

            const saveCurrentOs = (silent = false) => {
                if (!currentOs) return Promise.resolve();
                return fetch(`/api/os/${currentOs.id}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json', 'Authorization': auth.token },
                    body: JSON.stringify({
                        client: currentOs.client,
                        services: currentOs.services,
                        parts: currentOs.parts,
                        observations: currentOs.observations,
                        fromLaudo: currentOs.fromLaudo
                    })
                }).then(r => r.json().then(d => ({ status: r.status, d }))).then(({ status, d }) => {
                    if (d && d.id) {
                        setCurrentOs(d);
                        fetchOsDrafts();
                        if (!silent) alert('Rascunho salvo!');
                        return d;
                    } else if (status === 404 && currentOs.omieOsId) {
                        // Draft sumiu desse usuário mas a OS Omie existe - re-importa automaticamente
                        if (!silent) alert('Rascunho não estava salvo nesta conta. Re-importando do Omie...');
                        return fetch('/api/os/importar-omie', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json', 'Authorization': auth.token },
                            body: JSON.stringify({ nCodOS: currentOs.omieOsId })
                        }).then(r => r.json()).then(re => {
                            if (re.id) {
                                // Mantém os dados editados pelo usuário, mas atualiza o id local
                                const merged = { ...currentOs, id: re.id, status: 'imported', omieOsId: re.omieOsId, omieOsNumber: re.omieOsNumber };
                                // PERSISTE no disco via PUT com os dados editados pelo usuário
                                return fetch(`/api/os/${re.id}`, {
                                    method: 'PUT',
                                    headers: { 'Content-Type': 'application/json', 'Authorization': auth.token },
                                    body: JSON.stringify({
                                        client: merged.client,
                                        services: merged.services,
                                        parts: merged.parts,
                                        observations: merged.observations,
                                        fromLaudo: merged.fromLaudo
                                    })
                                }).then(r2 => r2.json()).then(persisted => {
                                    const final = persisted && persisted.id ? persisted : merged;
                                    setCurrentOs(final);
                                    fetchOsDrafts();
                                    return final;
                                });
                            }
                            return null;
                        });
                    } else if (d.error) {
                        alert(d.error);
                        return null;
                    }
                    return null;
                });
            };

            const deleteOs = (id) => {
                if (!confirm('Excluir este rascunho de OS?')) return;
                fetch(`/api/os/${id}`, { method: 'DELETE', headers: { 'Authorization': auth.token } })
                    .then(() => {
                        if (currentOs && currentOs.id === id) setCurrentOs(null);
                        fetchOsDrafts();
                    });
            };

            // Só oferece limpar quando OS + PDF + Fotos já foram todos enviados ao Omie.
            const maybeOfferClearAfterOmie = (os) => {
                if (os && os.status === 'sent' && os.pdfAnexado && os.fotosAnexadas) {
                    if (confirm('OS, PDF e Fotos enviados ao Omie! Deseja limpar o laudo e voltar pra lista, pra começar a próxima?')) {
                        clearCurrentReport();
                        setCurrentOs(null);
                    }
                }
            };

            const sendOsToOmie = () => {
                if (!currentOs) return;
                setOsSendError('');
                saveCurrentOs(true).then((savedOs) => {
                    // Usa o id atualizado (caso tenha sido re-importado) ou o atual
                    const osId = (savedOs && savedOs.id) || currentOs.id;
                    fetch(`/api/os/${osId}/send`, {
                        method: 'POST',
                        headers: { 'Authorization': auth.token }
                    }).then(r => r.json().then(data => ({status: r.status, data}))).then(({status, data}) => {
                        if (data.id && data.status === 'sent') {
                            setCurrentOs(data);
                            fetchOsDrafts();
                            let msg = `OS atualizada no Omie! Número: ${data.omieOsNumber || data.omieOsId}`;
                            if (data.pedidoVendaNumero) msg += `\nPedido de Venda das peças: nº ${data.pedidoVendaNumero}`;
                            if (data.warning) msg += `\n\n⚠️ ${data.warning}`;
                            alert(msg);
                            maybeOfferClearAfterOmie(data);
                        } else {
                            setOsSendError(data.error || 'Erro ao enviar');
                        }
                    });
                });
            };

            const generateOsFromCurrentLaudo = () => {
                const clientField = headerConfig.find(f => f.id === 'client');
                const defectField = headerConfig.find(f => f.id === 'defect');
                const clientName = clientField ? (headerData[clientField.id] || '') : '';
                const defect = defectField ? (headerData[defectField.id] || '') : '';
                const selectedModel = models.find(m => m.id === headerData.selectedTemplateId);
                const modelName = selectedModel ? selectedModel.name : '';
                const obs = [
                    modelName && `Modelo: ${modelName}`,
                    defect && `Defeito alegado pelo cliente: ${defect}`
                ].filter(Boolean).join('\\n\\n');
                createNewOs({
                    fromLaudo: { client: clientName, model: modelName, defect, generatedAt: new Date().toISOString() },
                    client: { omieClientId: null, name: clientName, document: '', email: '', phone: '' },
                    observations: obs
                });
            };

            // ---- helpers Omie search ----
            const [clienteMsg, setClienteMsg] = useState('');
            const [servicoMsg, setServicoMsg] = useState('');
            const [produtoMsg, setProdutoMsg] = useState('');

            const searchClientes = (q) => {
                setClienteMsg('Buscando...');
                fetch(`/api/omie/clientes?q=${encodeURIComponent(q || '')}`, { headers: { 'Authorization': auth.token } })
                    .then(r => r.json()).then(d => {
                        setClienteResults(d.items || []);
                        if (d.error) setClienteMsg('Erro: ' + d.error);
                        else if (!d.items || d.items.length === 0) setClienteMsg('Nenhum cliente encontrado no Omie.');
                        else setClienteMsg('');
                    }).catch(() => setClienteMsg('Erro de conexão'));
            };
            const searchServicos = (q) => {
                setServicoMsg('Buscando...');
                fetch(`/api/omie/servicos?q=${encodeURIComponent(q || '')}`, { headers: { 'Authorization': auth.token } })
                    .then(r => r.json()).then(d => {
                        setServicoResults(d.items || []);
                        if (d.error) setServicoMsg('Erro: ' + d.error);
                        else if (!d.items || d.items.length === 0) setServicoMsg('Nenhum serviço encontrado no catálogo Omie.');
                        else setServicoMsg(`${d.items.length} serviço(s) encontrado(s).`);
                    }).catch(() => setServicoMsg('Erro de conexão'));
            };
            const searchProdutos = (q) => {
                setProdutoMsg('Buscando...');
                fetch(`/api/omie/produtos?q=${encodeURIComponent(q || '')}`, { headers: { 'Authorization': auth.token } })
                    .then(r => r.json()).then(d => {
                        setProdutoResults(d.items || []);
                        if (d.error) setProdutoMsg('Erro: ' + d.error);
                        else if (!d.items || d.items.length === 0) setProdutoMsg('Nenhuma peça encontrada no catálogo Omie.');
                        else setProdutoMsg(`${d.items.length} peça(s) encontrada(s).`);
                    }).catch(() => setProdutoMsg('Erro de conexão'));
            };

            const createOmieCliente = (data) => {
                return fetch('/api/omie/clientes', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': auth.token },
                    body: JSON.stringify(data)
                }).then(r => r.json());
            };

            const irParaLaudoDesta = () => {
                // Auto-preenche o cabeçalho do laudo com dados da OS atual
                if (currentOs) {
                    const patch = {};
                    const clientField = headerConfig.find(f => f.id === 'client');
                    const defectField = headerConfig.find(f => f.id === 'defect');
                    if (clientField && currentOs.client?.name) {
                        patch[clientField.id] = currentOs.client.name;
                    }
                    if (defectField) {
                        // Puxa a "Descrição detalhada do Serviço" (preenchida pelo vendedor no Omie)
                        // de todos os serviços; se não houver, cai pra observações da OS.
                        const descServicos = (currentOs.services || [])
                            .map(s => (s.description || '').trim())
                            .filter(Boolean)
                            .join('\\n\\n');
                        const fonteDefeito = descServicos || currentOs.observations || '';
                        // Só sobrescreve defect se estiver vazio (não atropela o que técnico já preencheu)
                        if (fonteDefeito && !headerData[defectField.id]) {
                            patch[defectField.id] = fonteDefeito;
                        }
                    }
                    if (Object.keys(patch).length > 0) {
                        setHeaderData(prev => ({ ...prev, ...patch }));
                    }
                }
                setActiveTab('report');
            };

            const fetchOmieAbertas = () => {
                setLoadingAbertas(true);
                fetch('/api/omie/os/abertas', { headers: { 'Authorization': auth.token } })
                    .then(r => r.json()).then(d => {
                        setOmieAbertas(d.items || []);
                        setLoadingAbertas(false);
                    }).catch(() => setLoadingAbertas(false));
            };

            const importarOsDoOmie = (nCodOS) => {
                fetch('/api/os/importar-omie', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': auth.token },
                    body: JSON.stringify({ nCodOS })
                }).then(r => r.json()).then(d => {
                    if (d.id) {
                        setCurrentOs(d);
                        fetchOsDrafts();
                    } else {
                        alert(d.error || 'Erro ao importar OS');
                    }
                });
            };

            const anexarFotosLaudo = async () => {
                console.log('[anexarFotosLaudo] iniciando', { os: currentOs, fotos: reportImages?.length });
                if (!currentOs || !currentOs.omieOsId) {
                    alert('A OS precisa estar enviada/importada do Omie.');
                    return;
                }
                if (!reportImages || reportImages.length === 0) {
                    alert('Nenhuma foto no laudo atual. Adicione fotos na aba "Preencher Laudo" primeiro.');
                    return;
                }
                if (!confirm(`Anexar ${reportImages.length} foto(s) à OS no Omie como ZIP?`)) return;
                alert('Enviando fotos... aguarde.');

                try {
                    const resp = await fetch(`/api/os/${currentOs.id}/anexar-fotos`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'Authorization': auth.token },
                        body: JSON.stringify({ photos: reportImages })
                    });
                    const text = await resp.text();
                    let data;
                    try { data = JSON.parse(text); }
                    catch (e) { alert(`Erro: resposta inválida do servidor (HTTP ${resp.status}). Conteúdo: ${text.substring(0, 200)}`); return; }
                    if (data.success) {
                        alert(`${data.count} foto(s) anexada(s) com sucesso!`);
                        const nextOs = { ...currentOs, fotosAnexadas: true, fotosCount: data.count };
                        setCurrentOs(nextOs);
                        fetchOsDrafts();
                        maybeOfferClearAfterOmie(nextOs);
                    } else {
                        alert('Erro do servidor: ' + (data.error || `HTTP ${resp.status}`));
                    }
                } catch (err) {
                    console.error('[anexarFotosLaudo] erro', err);
                    alert('Erro de rede: ' + (err.message || err));
                }
            };

            const anexarLaudoPDF = async () => {
                if (!currentOs || !currentOs.omieOsId) {
                    alert('A OS precisa estar enviada/importada do Omie antes de anexar o PDF.');
                    return;
                }
                if (!confirm('Gerar PDF do laudo no servidor e anexar à OS no Omie?')) return;
                alert('Gerando PDF e enviando... aguarde alguns segundos.');

                // Monta o payload com os dados atuais do laudo
                const selectedModel = models.find(m => m.id === headerData.selectedTemplateId);
                const payload = {
                    headerConfig,
                    headerData,
                    answers,
                    questions: selectedModel ? selectedModel.questions : [],
                    diagrams: selectedModel ? selectedModel.diagrams : [],
                    diagramMarks,
                    reportImages,
                    logo,
                    technician: (auth.firstName ? `${auth.firstName} ${auth.lastName||''}` : auth.token).trim(),
                    technicianSignature: headerData.technicianSignature,
                    showSignatures: headerData.showSignatures !== false,
                    modelName: selectedModel ? selectedModel.name : '',
                    cellAnalysis: selectedModel ? selectedModel.cellAnalysis : null,
                    cellVoltagesList: selectedModel ? (cellVoltages[selectedModel.id] || []) : []
                };

                try {
                    const resp = await fetch(`/api/os/${currentOs.id}/gerar-pdf-anexar`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'Authorization': auth.token },
                        body: JSON.stringify(payload)
                    });
                    const text = await resp.text();
                    let data;
                    try { data = JSON.parse(text); }
                    catch { alert(`Erro: resposta inválida (HTTP ${resp.status}): ${text.substring(0,200)}`); return; }
                    if (data.success) {
                        alert('PDF do laudo anexado à OS no Omie!');
                        const nextOs = { ...currentOs, pdfAnexado: true };
                        setCurrentOs(nextOs);
                        fetchOsDrafts();
                        maybeOfferClearAfterOmie(nextOs);
                    } else {
                        alert('Erro: ' + (data.error || `HTTP ${resp.status}`));
                    }
                } catch (err) {
                    alert('Erro: ' + (err.message || err));
                }
            };

            const osTotal = (os) => {
                if (!os) return 0;
                const sumS = (os.services || []).reduce((a, s) => a + (parseFloat(s.quantity || 0) * parseFloat(s.unitPrice || 0)), 0);
                const sumP = (os.parts || []).reduce((a, p) => a + (parseFloat(p.quantity || 0) * parseFloat(p.unitPrice || 0)), 0);
                return sumS + sumP;
            };

            const handleLogin = (e) => {
                e.preventDefault();
                setLoginError("");
                const username = e.target.username.value;
                const password = e.target.password.value;

                fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                }).then(r => r.json().then(data => ({status: r.status, data}))).then(({status, data}) => {
                    if (data.success) {
                        const newAuth = { token: data.token, username: data.username, role: data.role, firstName: data.firstName, lastName: data.lastName };
                        localStorage.setItem('smartReportAuth', JSON.stringify(newAuth));
                        setAuth(newAuth);
                        if (data.mustResetPassword) setMustChangePwd(true);
                    } else {
                        setLoginError(data.message || "Erro no login");
                    }
                }).catch(() => setLoginError("Erro de conexão"));
            };

            const handleRegister = (e) => {
                e.preventDefault();
                setRegisterMsg({ type: '', text: '' });
                const f = e.target;
                if (f.password.value !== f.confirmPassword.value) {
                    setRegisterMsg({ type: 'error', text: 'As senhas não coincidem.' });
                    return;
                }
                const payload = {
                    username: f.username.value,
                    password: f.password.value,
                    firstName: f.firstName.value,
                    lastName: f.lastName.value,
                    email: f.email.value,
                    phone: f.phone.value
                };
                fetch('/api/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                }).then(r => r.json()).then(data => {
                    if (data.success) {
                        setRegisterMsg({ type: 'success', text: data.message || 'Conta criada! Aguarde aprovação.' });
                        f.reset();
                    } else {
                        setRegisterMsg({ type: 'error', text: data.message || 'Erro ao cadastrar.' });
                    }
                }).catch(() => setRegisterMsg({ type: 'error', text: 'Erro de conexão' }));
            };

            const handleChangePassword = (e) => {
                e.preventDefault();
                setPwdChangeMsg("");
                const f = e.target;
                if (f.newPassword.value !== f.confirmPassword.value) {
                    setPwdChangeMsg("As senhas não coincidem.");
                    return;
                }
                fetch('/api/change-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': auth.token },
                    body: JSON.stringify({ currentPassword: f.currentPassword.value, newPassword: f.newPassword.value })
                }).then(r => r.json()).then(data => {
                    if (data.success) {
                        setMustChangePwd(false);
                        f.reset();
                        setPwdChangeMsg("");
                    } else {
                        setPwdChangeMsg(data.message || "Erro ao trocar senha");
                    }
                });
            };

            const handleLogout = () => {
                // Invalida a sessão no servidor (best-effort)
                try {
                    if (auth && auth.token) {
                        fetch('/api/logout', { method: 'POST', headers: { 'Authorization': auth.token } }).catch(() => {});
                    }
                } catch (e) {}
                localStorage.removeItem('smartReportAuth');
                setAuth(null);
                setIsLoaded(false);
                setActiveTab('report');
                // Limpa estados específicos do usuário pra não vazar pra próxima conta
                setCurrentOs(null);
                setOsDrafts([]);
                setOmieAbertas([]);
                setHeaderData({});
                setAnswers({});
                setDiagramMarks({});
                setReportImages([]);
                setCellVoltages({});
                setLaudosList([]);
            };

            if (!auth) {
                return html`
                    <div className="min-h-screen bg-slate-100 flex items-center justify-center p-4">
                        <div className="bg-white p-8 rounded-2xl shadow-xl w-full max-w-md">
                            <div className="text-center mb-6">
                                ${publicLogo
                                    ? html`<img src=${publicLogo} alt="BioDron" className="h-16 w-auto object-contain mx-auto mb-3" />`
                                    : html`<i className="ph-fill ph-device-mobile text-blue-600 text-5xl mb-2"></i>`}
                                <h1 className="text-2xl font-bold text-slate-800">Biodron Smart Report Pro</h1>
                                <p className="text-sm text-slate-500">${authMode === 'login' ? 'Faça login para acessar seu painel' : 'Crie sua conta — aguarde aprovação do administrador'}</p>
                            </div>

                            <div className="flex bg-slate-100 p-1 rounded-lg mb-6">
                                <button type="button" onClick=${() => { setAuthMode('login'); setRegisterMsg({type:'',text:''}); setLoginError(''); }} className=${`flex-1 py-2 rounded-md text-sm font-medium transition ${authMode === 'login' ? 'bg-white text-blue-700 shadow' : 'text-slate-600'}`}>Entrar</button>
                                <button type="button" onClick=${() => { setAuthMode('register'); setRegisterMsg({type:'',text:''}); setLoginError(''); }} className=${`flex-1 py-2 rounded-md text-sm font-medium transition ${authMode === 'register' ? 'bg-white text-blue-700 shadow' : 'text-slate-600'}`}>Criar conta</button>
                            </div>

                            ${authMode === 'login' ? html`
                                <form onSubmit=${handleLogin} className="space-y-4">
                                    <div>
                                        <label className="block text-sm font-medium text-slate-700 mb-1">Usuário</label>
                                        <input name="username" type="text" required className="w-full p-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none" placeholder="Digite seu usuário" />
                                    </div>
                                    <div>
                                        <label className="block text-sm font-medium text-slate-700 mb-1">Senha</label>
                                        <input name="password" type="password" required className="w-full p-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none" placeholder="••••••••" />
                                    </div>
                                    ${loginError && html`<div className="text-red-500 text-sm font-medium text-center bg-red-50 p-2 rounded">${loginError}</div>`}
                                    <button type="submit" className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold p-3 rounded-lg transition mt-2">Entrar no Sistema</button>
                                </form>
                            ` : html`
                                <form onSubmit=${handleRegister} className="space-y-3">
                                    <div className="grid grid-cols-2 gap-2">
                                        <div>
                                            <label className="block text-xs font-medium text-slate-700 mb-1">Nome *</label>
                                            <input name="firstName" type="text" required className="w-full p-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none text-sm" />
                                        </div>
                                        <div>
                                            <label className="block text-xs font-medium text-slate-700 mb-1">Sobrenome *</label>
                                            <input name="lastName" type="text" required className="w-full p-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none text-sm" />
                                        </div>
                                    </div>
                                    <div>
                                        <label className="block text-xs font-medium text-slate-700 mb-1">E-mail *</label>
                                        <input name="email" type="email" required className="w-full p-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none text-sm" placeholder="voce@email.com" />
                                    </div>
                                    <div>
                                        <label className="block text-xs font-medium text-slate-700 mb-1">Telefone *</label>
                                        <input name="phone" type="tel" required className="w-full p-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none text-sm" placeholder="(11) 99999-9999"
                                            onInput=${(e) => {
                                                let v = e.target.value.replace(/\\D/g, '').slice(0, 11);
                                                if (v.length > 6) v = '(' + v.slice(0,2) + ') ' + v.slice(2,7) + '-' + v.slice(7);
                                                else if (v.length > 2) v = '(' + v.slice(0,2) + ') ' + v.slice(2);
                                                e.target.value = v;
                                            }} />
                                    </div>
                                    <div className="border-t border-slate-200 pt-3 mt-3">
                                        <label className="block text-xs font-medium text-slate-700 mb-1">Login (nome de usuário) *</label>
                                        <input name="username" type="text" required pattern="[a-zA-Z0-9_.-]{3,30}" title="3-30 caracteres: letras, números, . _ -" className="w-full p-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none text-sm" placeholder="ex: jose.silva" />
                                    </div>
                                    <div className="grid grid-cols-2 gap-2">
                                        <div>
                                            <label className="block text-xs font-medium text-slate-700 mb-1">Senha * (min. 6)</label>
                                            <input name="password" type="password" required minLength="6" className="w-full p-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none text-sm" />
                                        </div>
                                        <div>
                                            <label className="block text-xs font-medium text-slate-700 mb-1">Confirmar senha *</label>
                                            <input name="confirmPassword" type="password" required minLength="6" className="w-full p-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none text-sm" />
                                        </div>
                                    </div>
                                    ${registerMsg.text && html`
                                        <div className=${`text-sm font-medium text-center p-2 rounded ${registerMsg.type === 'success' ? 'text-green-700 bg-green-50' : 'text-red-600 bg-red-50'}`}>${registerMsg.text}</div>
                                    `}
                                    <button type="submit" className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold p-3 rounded-lg transition mt-2">Criar Conta</button>
                                </form>
                            `}
                        </div>
                    </div>
                `;
            }

            // Tela obrigatória de troca de senha (após login com senha temporária)
            if (mustChangePwd) {
                return html`
                    <div className="min-h-screen bg-slate-100 flex items-center justify-center p-4">
                        <div className="bg-white p-8 rounded-2xl shadow-xl w-full max-w-sm">
                            <div className="text-center mb-6">
                                <i className="ph-fill ph-lock-key text-amber-600 text-5xl mb-2"></i>
                                <h1 className="text-xl font-bold text-slate-800">Troca de Senha Obrigatória</h1>
                                <p className="text-sm text-slate-500 mt-1">Sua senha foi resetada pelo administrador. Defina uma nova senha pra continuar.</p>
                            </div>
                            <form onSubmit=${handleChangePassword} className="space-y-3">
                                <div>
                                    <label className="block text-sm font-medium text-slate-700 mb-1">Senha atual (a temporária)</label>
                                    <input name="currentPassword" type="password" required className="w-full p-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none" />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-slate-700 mb-1">Nova senha (min. 6)</label>
                                    <input name="newPassword" type="password" required minLength="6" className="w-full p-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none" />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-slate-700 mb-1">Confirmar nova senha</label>
                                    <input name="confirmPassword" type="password" required minLength="6" className="w-full p-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none" />
                                </div>
                                ${pwdChangeMsg && html`<div className="text-red-600 text-sm font-medium text-center bg-red-50 p-2 rounded">${pwdChangeMsg}</div>`}
                                <button type="submit" className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold p-3 rounded-lg transition">Salvar Nova Senha</button>
                                <button type="button" onClick=${handleLogout} className="w-full text-sm text-slate-500 hover:text-slate-700 mt-2">Sair</button>
                            </form>
                        </div>
                    </div>
                `;
            }

            if (!isLoaded) return html`<div className="flex justify-center items-center h-screen text-xl font-bold text-slate-500"><i className="ph ph-spinner animate-spin mr-2"></i> Carregando dados do usuário...</div>`;

            const finalizarCompleto = async () => {
                if (!currentOs) return;
                if (!confirm('Confirma que o laudo e o orçamento estão completamente preenchidos?\\n\\nO sistema vai:\\n1. Atualizar a OS no Omie\\n2. Gerar e anexar o PDF do laudo\\n3. Anexar as fotos (se houver)\\n4. Limpar os dados do laudo')) return;

                setFinalizando(true);
                setOsSendError('');
                const erros = [];
                let osAtual = currentOs;

                // Etapa 1: salvar + enviar/atualizar OS no Omie
                try {
                    const savedOs = await saveCurrentOs(true);
                    const osId = (savedOs && savedOs.id) || osAtual.id;
                    const r1 = await fetch(`/api/os/${osId}/send`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'Authorization': auth.token }
                    });
                    const d1 = await r1.json();
                    if (d1.omieOsId || d1.omieOsNumber) {
                        osAtual = { ...osAtual, ...d1 };
                        setCurrentOs(osAtual);
                    } else {
                        erros.push('Omie: ' + (d1.error || 'erro ao enviar OS'));
                    }
                } catch (e) { erros.push('Omie: ' + (e.message || e)); }

                // Etapa 2: gerar PDF e anexar
                if (!erros.length || osAtual.omieOsId) {
                    try {
                        const selectedModel = models.find(m => m.id === headerData.selectedTemplateId);
                        const pdfPayload = {
                            headerConfig, headerData, answers,
                            questions: selectedModel ? selectedModel.questions : [],
                            diagrams: selectedModel ? selectedModel.diagrams : [],
                            diagramMarks, reportImages, logo,
                            technician: (auth.firstName ? `${auth.firstName} ${auth.lastName||''}` : auth.token).trim(),
                            technicianSignature: headerData.technicianSignature,
                            showSignatures: headerData.showSignatures !== false,
                            modelName: selectedModel ? selectedModel.name : '',
                            cellAnalysis: selectedModel ? selectedModel.cellAnalysis : null,
                            cellVoltagesList: selectedModel ? (cellVoltages[selectedModel.id] || []) : []
                        };
                        const r2 = await fetch(`/api/os/${osAtual.id}/gerar-pdf-anexar`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json', 'Authorization': auth.token },
                            body: JSON.stringify(pdfPayload)
                        });
                        const d2 = await r2.json();
                        if (d2.success) {
                            osAtual = { ...osAtual, pdfAnexado: true };
                            setCurrentOs(osAtual);
                        } else {
                            erros.push('PDF: ' + (d2.error || 'erro ao anexar'));
                        }
                    } catch (e) { erros.push('PDF: ' + (e.message || e)); }
                }

                // Etapa 3: anexar fotos (apenas se houver fotos)
                if (reportImages && reportImages.length > 0 && osAtual.omieOsId) {
                    try {
                        const r3 = await fetch(`/api/os/${osAtual.id}/anexar-fotos`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json', 'Authorization': auth.token },
                            body: JSON.stringify({ photos: reportImages })
                        });
                        const d3 = await r3.json();
                        if (d3.success) {
                            osAtual = { ...osAtual, fotosAnexadas: true, fotosCount: d3.count };
                            setCurrentOs(osAtual);
                        } else {
                            erros.push('Fotos: ' + (d3.error || 'erro ao anexar'));
                        }
                    } catch (e) { erros.push('Fotos: ' + (e.message || e)); }
                }

                setFinalizando(false);
                fetchOsDrafts();

                if (erros.length) {
                    alert('Concluído com erros:\\n' + erros.join('\\n') + '\\n\\nVerifique e tente as etapas individualmente.');
                } else {
                    alert('Tudo enviado com sucesso! OS atualizada, PDF e fotos anexados no Omie.\\n\\nOs dados do laudo serão limpos.');
                    clearCurrentReport();
                    setCurrentOs(null);
                }
            };

            const clearCurrentReport = () => {
                const resetHeader = {
                    date: new Date().toISOString().split('T')[0],
                    selectedTemplateId: headerData.selectedTemplateId,
                    showSignatures: headerData.showSignatures !== false,
                    technicianSignature: ''
                };
                setHeaderData(resetHeader);
                setAnswers({});
                setDiagramMarks({});
                setReportImages([]);
                setCellVoltages({});
            };

            // ---- Compressão de imagens (max 1200px, JPEG 75%) ----
            const compressImage = (dataUrl, maxW = 1200) => new Promise(resolve => {
                const img = new Image();
                img.onload = () => {
                    const scale = img.width > maxW ? maxW / img.width : 1;
                    const canvas = document.createElement('canvas');
                    canvas.width = Math.round(img.width * scale);
                    canvas.height = Math.round(img.height * scale);
                    canvas.getContext('2d').drawImage(img, 0, 0, canvas.width, canvas.height);
                    resolve(canvas.toDataURL('image/jpeg', 0.75));
                };
                img.onerror = () => resolve(dataUrl);
                img.src = dataUrl;
            });

            // ---- Histórico de Laudos ----
            const saveLaudo = async (name) => {
                // Comprime as imagens novamente pra ficar leve no histórico
                const compressed = await Promise.all((reportImages || []).map(async img => ({
                    ...img, src: await compressImage(img.src)
                })));
                const state = { headerData, answers, diagramMarks, reportImages: compressed, pdfMargin, cellVoltages };
                const clientField = headerConfig.find(f => f.id === 'client');
                const clientName = clientField ? (headerData[clientField.id] || '') : '';
                const finalName = name || (clientName ? `${clientName} — ${headerData.date || ''}` : 'Laudo ' + new Date().toLocaleDateString('pt-BR'));
                fetch('/api/laudos', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': auth.token },
                    body: JSON.stringify({ action: 'save', name: finalName, date: headerData.date, state })
                }).then(r => r.json()).then(d => { if(d.success) { alert('Laudo salvo!'); fetchLaudos(); } });
            };

            const loadLaudo = (id) => {
                fetch('/api/laudos', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': auth.token },
                    body: JSON.stringify({ action: 'load', id })
                }).then(r => r.json()).then(laudo => {
                    if (laudo && laudo.state) {
                        const s = laudo.state;
                        setHeaderData(s.headerData || {});
                        setAnswers(s.answers || {});
                        setDiagramMarks(s.diagramMarks || {});
                        setReportImages(s.reportImages || []);
                        setPdfMargin(s.pdfMargin || '1.5cm');
                        setCellVoltages(s.cellVoltages || {});
                        setLaudosModalOpen(false);
                        setActiveTab('report');
                    }
                });
            };

            const duplicateLaudo = (id) => {
                fetch('/api/laudos', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': auth.token },
                    body: JSON.stringify({ action: 'duplicate', id })
                }).then(r => r.json()).then(() => fetchLaudos());
            };

            const deleteLaudo = (id) => {
                fetch('/api/laudos', {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json', 'Authorization': auth.token },
                    body: JSON.stringify({ id })
                }).then(() => fetchLaudos());
            };

            // ---- Backup/Import config (admin) ----
            const exportConfig = () => {
                fetch('/api/export-config', { headers: { 'Authorization': auth.token } })
                    .then(r => r.json()).then(data => {
                        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = `biodron_backup_${new Date().toISOString().slice(0,10)}.json`;
                        a.click();
                        URL.revokeObjectURL(url);
                    });
            };

            const importConfig = (file) => {
                if (!confirm('Importar este arquivo vai SOBRESCREVER configs/usuários/laudos atuais. Confirma?')) return;
                const reader = new FileReader();
                reader.onload = (e) => {
                    try {
                        const data = JSON.parse(e.target.result);
                        fetch('/api/import-config', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json', 'Authorization': auth.token },
                            body: JSON.stringify(data)
                        }).then(r => r.json()).then(d => {
                            if (d.success) { alert('Importado! Recarregando...'); window.location.reload(); }
                            else alert('Erro: ' + (d.error || 'desconhecido'));
                        });
                    } catch (err) { alert('Arquivo inválido: ' + err.message); }
                };
                reader.readAsText(file);
            };

            // ---- Geração de texto com IA (Gemini) ----
            // ---- Gera PDF no servidor (mesmo layout do anexo Omie) e baixa ----
            const _montarPayloadLaudo = () => {
                const selectedModel = models.find(m => m.id === headerData.selectedTemplateId);
                const payload = {
                    headerConfig,
                    headerData,
                    answers,
                    questions: selectedModel ? selectedModel.questions : [],
                    diagrams: selectedModel ? selectedModel.diagrams : [],
                    diagramMarks,
                    reportImages,
                    logo,
                    technician: (auth.firstName ? `${auth.firstName} ${auth.lastName||''}` : auth.token).trim(),
                    technicianSignature: headerData.technicianSignature,
                    showSignatures: headerData.showSignatures !== false,
                    modelName: selectedModel ? selectedModel.name : '',
                    cellAnalysis: selectedModel ? selectedModel.cellAnalysis : null,
                    cellVoltagesList: selectedModel ? (cellVoltages[selectedModel.id] || []) : []
                };
                // Se há uma OS aberta com serviços/peças, inclui a página de Orçamento no PDF
                if (currentOs && ((currentOs.services||[]).length || (currentOs.parts||[]).length)) {
                    payload.osQuote = {
                        osNumber: currentOs.omieOsNumber || '',
                        clientName: (currentOs.client && currentOs.client.name) || '',
                        clientDoc: (currentOs.client && currentOs.client.document) || '',
                        services: currentOs.services || [],
                        parts: currentOs.parts || [],
                        paymentTerm: 'À vista'
                    };
                }
                return payload;
            };

            const baixarPdfLaudo = async () => {
                const clientField = headerConfig.find(f => f.id === 'client');
                const clientName = clientField ? (headerData[clientField.id] || 'laudo') : 'laudo';
                const filename = `laudo_${clientName.replace(/[^a-zA-Z0-9_-]/g, '_')}.pdf`;
                const payload = { ..._montarPayloadLaudo(), filename };
                try {
                    const resp = await fetch('/api/gerar-pdf-download', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'Authorization': auth.token },
                        body: JSON.stringify(payload)
                    });
                    if (!resp.ok) {
                        const t = await resp.text();
                        alert('Erro ao gerar PDF: ' + t.substring(0, 200));
                        return;
                    }
                    const blob = await resp.blob();
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = filename;
                    a.click();
                    URL.revokeObjectURL(url);
                } catch (err) {
                    alert('Erro: ' + (err.message || err));
                }
            };

            const gerarTextoIA = async () => {
                const selectedModel = models.find(m => m.id === headerData.selectedTemplateId);
                setIaModalOpen(true);
                setIaLoading(true);
                setIaTexto('');

                // Monta resumo de células se houver
                let cellSummary = null;
                if (selectedModel && selectedModel.cellAnalysis && selectedModel.cellAnalysis.enabled) {
                    const volts = (cellVoltages[selectedModel.id] || []).map(v => parseFloat(v)).filter(v => !isNaN(v) && v > 0);
                    if (volts.length) {
                        const total = volts.reduce((s,v)=>s+v,0);
                        const maxV = Math.max(...volts), minV = Math.min(...volts);
                        const drop = maxV - minV;
                        const maxDrop = selectedModel.cellAnalysis.maxDropV || 0.2;
                        cellSummary = `${volts.length} células medidas. Tensão total ${total.toFixed(3)}V, máxima ${maxV.toFixed(3)}V, mínima ${minV.toFixed(3)}V, voltage drop ${drop.toFixed(3)}V (limite tolerado ${maxDrop.toFixed(3)}V). ${drop > maxDrop ? 'Células desbalanceadas acima do limite.' : 'Células dentro do limite de balanceamento.'}`;
                    }
                }

                try {
                    const resp = await fetch('/api/gerar-texto-ia', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'Authorization': auth.token },
                        body: JSON.stringify({
                            headerData, headerConfig, answers,
                            questions: selectedModel ? selectedModel.questions : [],
                            modelName: selectedModel ? selectedModel.name : '',
                            cellSummary
                        })
                    });
                    const data = await resp.json();
                    if (data.success) {
                        setIaTexto(data.texto);
                    } else {
                        setIaTexto('❌ Erro: ' + (data.error || 'desconhecido'));
                    }
                } catch (err) {
                    setIaTexto('❌ Erro de conexão: ' + (err.message || err));
                } finally {
                    setIaLoading(false);
                }
            };

            const copiarTextoIA = () => {
                navigator.clipboard?.writeText(iaTexto).then(() => alert('Texto copiado!'));
            };

            // ---- Download fotos como ZIP ----
            const downloadImagesZip = async () => {
                if (!reportImages || reportImages.length === 0) {
                    alert('Nenhuma foto adicionada ao laudo.');
                    return;
                }
                if (typeof JSZip === 'undefined') {
                    alert('Biblioteca JSZip não carregou. Faça hard refresh.');
                    return;
                }
                const zip = new JSZip();
                const folder = zip.folder('evidencias');
                for (let i = 0; i < reportImages.length; i++) {
                    const img = reportImages[i];
                    const base64 = (img.src || '').split(',')[1];
                    if (!base64) continue;
                    const ext = (img.src.indexOf('image/png') !== -1) ? 'png' : 'jpg';
                    const safeName = (img.caption || ('foto_' + (i+1))).replace(/[^a-zA-Z0-9_-]/g, '_');
                    folder.file(`${(i+1).toString().padStart(2,'0')}_${safeName}.${ext}`, base64, { base64: true });
                }
                const blob = await zip.generateAsync({ type: 'blob' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                const clientField = headerConfig.find(f => f.id === 'client');
                const clientName = clientField ? (headerData[clientField.id] || 'laudo') : 'laudo';
                a.download = `evidencias_${clientName.replace(/[^a-zA-Z0-9_-]/g, '_')}.zip`;
                a.click();
                URL.revokeObjectURL(url);
            };

            const handleLogoUpload = (e) => {
                const file = e.target.files[0];
                if (file) {
                    const reader = new FileReader();
                    reader.onloadend = () => setLogo(reader.result);
                    reader.readAsDataURL(file);
                }
            };

            const addHeaderField = () => {
                const newField = { id: 'hf_' + Date.now(), label: 'Novo Campo', type: 'text' };
                setHeaderConfig([...headerConfig, newField]);
            };

            const updateHeaderField = (id, key, value) => {
                setHeaderConfig(headerConfig.map(f => f.id === id ? { ...f, [key]: value } : f));
            };

            const removeHeaderField = (id) => {
                setHeaderConfig(headerConfig.filter(f => f.id !== id));
            };

            const handleFileSelect = (e) => {
                const files = Array.from(e.target.files);
                if (files.length === 0) return;

                setSourceModalOpen(false);

                const promises = files.map(file => {
                    return new Promise((resolve) => {
                        const reader = new FileReader();
                        reader.onloadend = () => {
                            resolve({
                                id: 'img_' + Date.now() + Math.random().toString(36).substr(2, 9),
                                src: reader.result,
                                caption: ''
                            });
                        };
                        reader.readAsDataURL(file);
                    });
                });

                Promise.all(promises).then(results => {
                    setPendingImages(results);
                });

                e.target.value = null;
            };

            const confirmPendingImages = async () => {
                // Comprime as fotos antes de adicionar (reduz tamanho)
                const compressed = await Promise.all(pendingImages.map(async img => ({
                    ...img,
                    src: await compressImage(img.src)
                })));
                setReportImages(prev => [...prev, ...compressed]);
                setPendingImages([]);
            };

            const removeReportImage = (id) => {
                setReportImages(prev => prev.filter(img => img.id !== id));
            };

            const updateReportImageCaption = (id, caption) => {
                setReportImages(prev => prev.map(img => img.id === id ? { ...img, caption } : img));
            };

            const handleDragStart = (e, index) => { setDraggedImgIndex(index); e.dataTransfer.effectAllowed = "move"; };
            const handleDragOver = (e, index) => { e.preventDefault(); if (draggedOverImgIndex !== index) setDraggedOverImgIndex(index); };
            const handleDragLeave = () => { setDraggedOverImgIndex(null); };
            const handleDrop = (e, dropIndex) => {
                e.preventDefault();
                if (draggedImgIndex === null) return;
                if (draggedImgIndex !== dropIndex) {
                    const newImages = [...reportImages];
                    const draggedItem = newImages[draggedImgIndex];
                    newImages.splice(draggedImgIndex, 1);
                    newImages.splice(dropIndex, 0, draggedItem);
                    setReportImages(newImages);
                }
                setDraggedImgIndex(null);
                setDraggedOverImgIndex(null);
            };

            const moveImage = (index, direction) => {
                if ((direction === -1 && index === 0) || (direction === 1 && index === reportImages.length - 1)) return;
                const newImages = [...reportImages];
                const temp = newImages[index];
                newImages[index] = newImages[index + direction];
                newImages[index + direction] = temp;
                setReportImages(newImages);
            };

            const currentEditingModel = models.find(m => m.id === editingModelId) || models[0] || null;

            const createNewModel = () => {
                const newModel = { id: 'model_' + Date.now(), name: 'Novo Modelo', questions: [], diagrams: [] };
                setModels([...models, newModel]);
                setEditingModelId(newModel.id);
            };

            const duplicateModel = (modelId) => {
                const source = models.find(m => m.id === modelId);
                if(source) {
                    const dup = { ...source, id: 'model_' + Date.now(), name: source.name + ' (Cópia)' };
                    setModels([...models, dup]);
                    setEditingModelId(dup.id);
                }
            };

            const deleteModel = (modelId) => {
                if(models.length === 1) return; // Segurança, não apaga o último
                const newModels = models.filter(m => m.id !== modelId);
                setModels(newModels);
                if(editingModelId === modelId) setEditingModelId(newModels[0].id);
                if(headerData.selectedTemplateId === modelId) setHeaderData({...headerData, selectedTemplateId: newModels[0].id});
            };

            const updateCurrentModel = (field, value) => setModels(models.map(m => m.id === editingModelId ? { ...m, [field]: value } : m));
            const updateCurrentModelQuestion = (qId, field, value) => setModels(models.map(m => m.id === editingModelId ? { ...m, questions: m.questions.map(q => q.id === qId ? { ...q, [field]: value } : q) } : m));
            const addQuestionToModel = () => setModels(models.map(m => m.id === editingModelId ? { ...m, questions: [...m.questions, { id: 'q_' + Date.now(), type: 'checkbox', label: 'Nova pergunta', subLabel: '' }] } : m));
            const removeQuestionFromModel = (qId) => setModels(models.map(m => m.id === editingModelId ? { ...m, questions: m.questions.filter(q => q.id !== qId) } : m));

            const handleDiagramUpload = (e) => {
                const file = e.target.files[0];
                if (file) {
                    const reader = new FileReader();
                    reader.onloadend = () => {
                        setModels(models.map(m => {
                            if (m.id !== editingModelId) return m;
                            return { ...m, diagrams: [...m.diagrams, { id: 'diag_' + Date.now(), name: 'Vista ' + (m.diagrams.length + 1), imageBase64: reader.result }] };
                        }));
                    };
                    reader.readAsDataURL(file);
                }
            };
            const removeDiagram = (diagId) => setModels(models.map(m => m.id === editingModelId ? { ...m, diagrams: m.diagrams.filter(d => d.id !== diagId) } : m));
            const renameDiagram = (diagId, newName) => setModels(models.map(m => m.id === editingModelId ? { ...m, diagrams: m.diagrams.map(d => d.id === diagId ? {...d, name: newName} : d) } : m));

            const handleAnswerChange = (id, field, value) => setAnswers(prev => ({ ...prev, [id]: { ...(prev[id] || {}), [field]: value } }));
            const handleDiagramClick = (e, diagId) => {
                const rect = e.currentTarget.getBoundingClientRect();
                const x = ((e.clientX - rect.left) / rect.width) * 100;
                const y = ((e.clientY - rect.top) / rect.height) * 100;
                setDiagramMarks(prev => ({ ...prev, [diagId]: [...(prev[diagId] || []), { id: Date.now().toString(), x, y }] }));
            };
            const undoLastMark = (diagId) => {
                setDiagramMarks(prev => {
                    const marks = prev[diagId] || [];
                    if (marks.length === 0) return prev;
                    return { ...prev, [diagId]: marks.slice(0, -1) };
                });
            };
            const clearDiagramMarks = (diagId) => setDiagramMarks(prev => ({ ...prev, [diagId]: [] }));

            const SignaturePad = ({ value, onChange }) => {
                const canvasRef = useRef(null);
                const isDrawing = useRef(false);
                const lastPos = useRef({ x: 0, y: 0 });

                useEffect(() => {
                    const canvas = canvasRef.current;
                    if (!canvas) return;
                    const ratio = window.devicePixelRatio || 1;
                    const rect = canvas.getBoundingClientRect();
                    canvas.width = rect.width * ratio;
                    canvas.height = rect.height * ratio;
                    const ctx = canvas.getContext('2d');
                    ctx.scale(ratio, ratio);
                    ctx.lineWidth = 2.5;
                    ctx.lineCap = 'round';
                    ctx.lineJoin = 'round';
                    ctx.strokeStyle = '#0f172a';
                    if (value) {
                        const img = new Image();
                        img.onload = () => ctx.drawImage(img, 0, 0, rect.width, rect.height);
                        img.src = value;
                    }
                }, []);

                const getPos = (e) => {
                    const rect = canvasRef.current.getBoundingClientRect();
                    const clientX = e.touches ? e.touches[0].clientX : e.clientX;
                    const clientY = e.touches ? e.touches[0].clientY : e.clientY;
                    return { x: clientX - rect.left, y: clientY - rect.top };
                };

                const start = (e) => {
                    e.preventDefault();
                    isDrawing.current = true;
                    lastPos.current = getPos(e);
                };

                const draw = (e) => {
                    if (!isDrawing.current) return;
                    e.preventDefault();
                    const ctx = canvasRef.current.getContext('2d');
                    const pos = getPos(e);
                    ctx.beginPath();
                    ctx.moveTo(lastPos.current.x, lastPos.current.y);
                    ctx.lineTo(pos.x, pos.y);
                    ctx.stroke();
                    lastPos.current = pos;
                };

                const end = () => {
                    if (!isDrawing.current) return;
                    isDrawing.current = false;
                    onChange(canvasRef.current.toDataURL('image/png'));
                };

                const clear = () => {
                    const canvas = canvasRef.current;
                    const ctx = canvas.getContext('2d');
                    ctx.clearRect(0, 0, canvas.width, canvas.height);
                    onChange('');
                };

                return html`
                    <div className="flex flex-col gap-2">
                        <canvas
                            ref=${canvasRef}
                            onMouseDown=${start} onMouseMove=${draw} onMouseUp=${end} onMouseLeave=${end}
                            onTouchStart=${start} onTouchMove=${draw} onTouchEnd=${end}
                            style=${{ touchAction: 'none', width: '100%', height: '200px', background: '#fff' }}
                            className="border-2 border-dashed border-slate-300 rounded-lg cursor-crosshair"
                        />
                        <div className="flex justify-between items-center">
                            <span className="text-xs text-slate-500"><i className="ph-fill ph-info"></i> Assine usando o dedo ou caneta (stylus)</span>
                            <button type="button" onClick=${clear} className="text-xs bg-red-100 hover:bg-red-200 text-red-700 px-3 py-1.5 rounded font-medium"><i className="ph-bold ph-eraser"></i> Limpar Assinatura</button>
                        </div>
                    </div>
                `;
            };

            const DiagramRenderer = ({ diagram, isPrintView = false }) => {
                const marks = diagramMarks[diagram.id] || [];
                return html`
                    <div className="flex flex-col gap-2 diagram-print-container mb-6">
                        <div className="flex justify-between items-center print:hidden">
                            <h4 className="font-semibold text-slate-700">${diagram.name}</h4>
                            <div className="flex gap-2">
                                <button onClick=${() => undoLastMark(diagram.id)} disabled=${marks.length === 0} className="text-xs bg-slate-200 hover:bg-slate-300 px-2 py-1 rounded disabled:opacity-50"><i className="ph-bold ph-arrow-u-up-left"></i> Desfazer</button>
                                <button onClick=${() => clearDiagramMarks(diagram.id)} disabled=${marks.length === 0} className="text-xs bg-red-100 hover:bg-red-200 text-red-700 px-2 py-1 rounded disabled:opacity-50"><i className="ph-bold ph-trash"></i> Limpar</button>
                            </div>
                        </div>
                        <h4 className="hidden print:block font-bold mb-1 text-sm text-center">${diagram.name}</h4>

                        <div className=${`relative border-2 border-slate-300 rounded-lg overflow-hidden bg-white ${!isPrintView ? 'diagram-interactive' : ''}`} onClick=${(e) => !isPrintView && handleDiagramClick(e, diagram.id)}>
                            <img src=${diagram.imageBase64} alt=${diagram.name} className="w-full h-auto block select-none pointer-events-none" />
                            ${marks.map((mark) => html`
                                <div key=${mark.id} className="absolute text-red-600 font-black leading-none drop-shadow-md select-none pointer-events-none" style=${{ left: `${mark.x}%`, top: `${mark.y}%`, transform: 'translate(-50%, -50%)', fontSize: isPrintView ? '20px' : 'clamp(16px, 3vw, 24px)' }}>X</div>
                            `)}
                        </div>
                        <div className="text-xs text-slate-500 font-medium print:hidden text-center mt-1">Toque na imagem para marcar <span className="text-red-500 font-bold">amassados ou trincados</span></div>
                    </div>
                `;
            };

            const renderReportForm = () => {
                const selectedModel = models.find(m => m.id === headerData.selectedTemplateId) || models[0];

                return html`
                    <div className="space-y-8 animate-in fade-in duration-300">
                        ${currentOs && (currentOs.status === 'imported' || currentOs.omieOsId) && html`
                            <div className="bg-indigo-50 border-2 border-indigo-300 p-4 rounded-xl flex items-center gap-3">
                                <i className="ph-fill ph-link text-indigo-600 text-2xl"></i>
                                <div className="flex-1">
                                    <div className="font-bold text-indigo-900">Laudo vinculado à OS #${currentOs.omieOsNumber || currentOs.id}</div>
                                    <div className="text-xs text-indigo-700">Cliente: ${currentOs.client?.name || '—'} · Após preencher, volte na OS para anexar o PDF.</div>
                                </div>
                                <button onClick=${() => setActiveTab('os')} className="bg-white hover:bg-indigo-100 border border-indigo-300 text-indigo-700 px-3 py-1.5 rounded text-sm font-medium">
                                    <i className="ph-bold ph-arrow-right"></i> Voltar pra OS
                                </button>
                            </div>
                        `}
                        <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                            <h2 className="text-xl font-semibold mb-4 text-slate-800 flex items-center gap-2">
                                <i className="ph-fill ph-file-text text-blue-600 text-2xl"></i> Informações Gerais
                            </h2>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div className="md:col-span-2 p-3 bg-blue-50 border border-blue-200 rounded-lg">
                                    <label className="block text-sm font-semibold text-blue-900 mb-1">Selecione o Modelo Base:</label>
                                    <select
                                        value=${headerData.selectedTemplateId || ''}
                                        onChange=${(e) => setHeaderData({...headerData, selectedTemplateId: e.target.value})}
                                        className="w-full p-2 border border-blue-300 rounded-lg bg-white focus:ring-2 focus:ring-blue-500 outline-none font-medium"
                                    >
                                        ${models.map(m => html`<option key=${m.id} value=${m.id}>${m.name}</option>`)}
                                    </select>
                                </div>

                                ${headerConfig.map(field => html`
                                    <div key=${field.id} className=${field.type === 'textarea' ? "md:col-span-2" : ""}>
                                        <label className="block text-sm font-medium text-slate-700 mb-1">${field.label}</label>
                                        ${field.type === 'textarea' ? html`
                                            <textarea value=${headerData[field.id] || ''} onChange=${e => setHeaderData({...headerData, [field.id]: e.target.value})} rows="3" className="w-full p-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none" ></textarea>
                                        ` : html`
                                            <input type="text" value=${headerData[field.id] || ''} onChange=${e => setHeaderData({...headerData, [field.id]: e.target.value})} className="w-full p-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none" />
                                        `}
                                    </div>
                                `)}
                            </div>
                        </div>

                        ${selectedModel && selectedModel.questions.length > 0 && html`
                            <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                                <h2 className="text-xl font-semibold mb-4 text-slate-800 flex items-center gap-2">
                                    <i className="ph-fill ph-list-checks text-blue-600 text-2xl"></i> Inspeção Física / Checklist
                                </h2>
                                <div className="space-y-4">
                                    ${selectedModel.questions.map(item => {
                                        const answer = answers[item.id] || {};
                                        const isChecked = answer.checked || false;
                                        return html`
                                            <div key=${item.id} className=${`p-4 rounded-lg border transition-all ${isChecked ? 'bg-blue-50 border-blue-200' : 'bg-slate-50 border-slate-200'}`}>
                                                <label className="flex items-start gap-3 cursor-pointer">
                                                    <input type="checkbox" checked=${isChecked} onChange=${e => handleAnswerChange(item.id, 'checked', e.target.checked)} className="mt-1 w-5 h-5 text-blue-600 rounded cursor-pointer" />
                                                    <div className="flex-1">
                                                        <span className=${`font-medium ${isChecked ? 'text-blue-900' : 'text-slate-700'}`}>${item.label}</span>
                                                        ${isChecked && item.type === 'checkbox_qty' && html`
                                                            <div className="mt-3 flex items-center gap-2">
                                                                <span className="text-sm text-blue-700">${item.subLabel || 'Quantidade:'}</span>
                                                                <input type="number" min="1" value=${answer.qty || ''} onChange=${e => handleAnswerChange(item.id, 'qty', e.target.value)} className="w-24 p-1 border border-blue-300 rounded outline-none" />
                                                            </div>
                                                        `}
                                                        ${isChecked && item.type === 'checkbox_text' && html`
                                                            <div className="mt-3">
                                                                <span className="block text-sm text-blue-700 mb-1">${item.subLabel || 'Descrição:'}</span>
                                                                <input type="text" value=${answer.text || ''} onChange=${e => handleAnswerChange(item.id, 'text', e.target.value)} className="w-full p-2 border border-blue-300 rounded outline-none" />
                                                            </div>
                                                        `}
                                                        ${item.type === 'text' && html`
                                                            <div className="mt-2">
                                                                <textarea value=${answer.text || ''} onChange=${e => handleAnswerChange(item.id, 'text', e.target.value)} className="w-full p-2 border border-slate-300 rounded outline-none" rows="2" />
                                                            </div>
                                                        `}
                                                    </div>
                                                </label>
                                            </div>
                                        `;
                                    })}
                                </div>
                            </div>
                        `}

                        ${selectedModel && selectedModel.cellAnalysis && selectedModel.cellAnalysis.enabled && html`
                            <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                                <h2 className="text-xl font-semibold mb-1 text-slate-800 flex items-center gap-2">
                                    <i className="ph-fill ph-lightning text-yellow-500 text-2xl"></i> Análise de Células
                                </h2>
                                <p className="text-sm text-slate-500 mb-4">Informe a tensão individual de cada célula. Pressione Enter para avançar.</p>
                                ${(() => {
                                    const ca = selectedModel.cellAnalysis;
                                    const numCells = ca.numCells || 14;
                                    const maxDrop = ca.maxDropV || 0.2;
                                    const modelKey = selectedModel.id;
                                    const voltages = cellVoltages[modelKey] || [];
                                    const vals = voltages.map(v => parseFloat(v)).filter(v => !isNaN(v) && v > 0);
                                    const total = vals.reduce((s,v)=>s+v,0);
                                    const avg = vals.length ? total/vals.length : 0;
                                    const maxV = vals.length ? Math.max(...vals) : 0;
                                    const minV = vals.length ? Math.min(...vals) : 0;
                                    const drop = maxV - minV;
                                    const dropPct = maxDrop > 0 ? Math.min(drop/maxDrop, 1) : 0;
                                    const getBalance = (d, mx) => {
                                        if (d === 0) return { label: '—', color: 'text-slate-400', bar: 'bg-slate-300' };
                                        const r = d / mx;
                                        if (r <= 0.25) return { label: 'Balanceada', color: 'text-emerald-600', bar: 'bg-emerald-500' };
                                        if (r <= 0.5) return { label: 'Levemente Desbalanceada', color: 'text-yellow-600', bar: 'bg-yellow-400' };
                                        if (r <= 0.75) return { label: 'Quase no Limite', color: 'text-orange-600', bar: 'bg-orange-500' };
                                        if (r <= 1.0) return { label: 'No Limite', color: 'text-red-600', bar: 'bg-red-500' };
                                        return { label: 'Totalmente Desbalanceada', color: 'text-red-800', bar: 'bg-red-700' };
                                    };
                                    const bal = vals.length >= 2 ? getBalance(drop, maxDrop) : null;
                                    return html`
                                        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                            <div className="md:col-span-2">
                                                <div className="grid gap-3" style=${{ gridTemplateRows: `repeat(${Math.ceil(numCells/4)}, auto)`, gridAutoFlow: 'column' }}>
                                                    ${Array.from({ length: numCells }, (_, i) => html`
                                                        <div key=${i} className="flex items-center gap-1.5">
                                                            <span className="text-xs font-bold text-slate-400 w-5 text-right">${i+1}</span>
                                                            <input
                                                                type="number" step="0.001" placeholder="0.000"
                                                                value=${voltages[i] || ''}
                                                                id=${'cv-' + modelKey + '-' + i}
                                                                onKeyDown=${(e) => {
                                                                    if (e.key === 'Enter') {
                                                                        e.preventDefault();
                                                                        const next = document.getElementById('cv-' + modelKey + '-' + (i+1));
                                                                        if (next) { next.focus(); next.select(); }
                                                                    }
                                                                }}
                                                                onChange=${(e) => {
                                                                    const arr = [...(cellVoltages[modelKey] || Array(numCells).fill(''))];
                                                                    while(arr.length < numCells) arr.push('');
                                                                    arr[i] = e.target.value;
                                                                    setCellVoltages({...cellVoltages, [modelKey]: arr});
                                                                }}
                                                                className="w-full p-1.5 text-sm border border-slate-300 rounded focus:ring-2 focus:ring-yellow-400 outline-none text-center font-mono"
                                                            />
                                                        </div>
                                                    `)}
                                                </div>
                                            </div>
                                            <div className="flex flex-col gap-3">
                                                <div className="bg-slate-50 border border-slate-200 rounded-lg p-4 space-y-2 text-sm">
                                                    <div className="flex justify-between"><span className="text-slate-500">Tensão Total</span><span className="font-bold font-mono">${total.toFixed(3)} V</span></div>
                                                    <div className="flex justify-between"><span className="text-slate-500">Tensão Média</span><span className="font-bold font-mono">${avg.toFixed(3)} V</span></div>
                                                    <div className="flex justify-between"><span className="text-slate-500">Máxima</span><span className="font-bold font-mono text-blue-600">${maxV.toFixed(3)} V</span></div>
                                                    <div className="flex justify-between"><span className="text-slate-500">Mínima</span><span className="font-bold font-mono text-blue-600">${minV.toFixed(3)} V</span></div>
                                                    <div className="flex justify-between border-t border-slate-200 pt-2"><span className="text-slate-500 font-bold">Voltage Drop</span><span className=${'font-bold font-mono ' + (drop > maxDrop ? 'text-red-600' : 'text-emerald-600')}>${drop.toFixed(3)} V</span></div>
                                                </div>
                                                ${bal && html`
                                                    <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
                                                        <p className="text-xs font-bold text-slate-500 uppercase mb-2">Status</p>
                                                        <div className="w-full bg-slate-200 rounded-full h-3 mb-2 overflow-hidden">
                                                            <div className=${'h-3 rounded-full transition-all ' + bal.bar} style=${{ width: Math.max(dropPct*100, 4) + '%' }}></div>
                                                        </div>
                                                        <p className=${'text-sm font-bold ' + bal.color}>${bal.label}</p>
                                                        <p className="text-xs text-slate-400 mt-1">Limite: ${maxDrop.toFixed(3)} V</p>
                                                    </div>
                                                `}
                                            </div>
                                        </div>
                                    `;
                                })()}
                            </div>
                        `}

                        ${selectedModel && selectedModel.diagrams.length > 0 && html`
                            <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                                <h2 className="text-xl font-semibold mb-2 text-slate-800 flex items-center gap-2">
                                    <i className="ph-fill ph-crosshair text-red-500 text-2xl"></i> Mapeamento Visual de Defeitos
                                </h2>
                                <p className="text-sm text-slate-500 mb-6 bg-red-50 text-red-700 p-3 rounded-md border border-red-100 flex items-center gap-2">
                                    <i className="ph-fill ph-info"></i> Toque nos diagramas abaixo para assinalar a presença de amassados, trincados ou danos físicos severos.
                                </p>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    ${selectedModel.diagrams.map(diag => html`<${DiagramRenderer} key=${diag.id} diagram=${diag} />`)}
                                </div>
                            </div>
                        `}

                        <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                            <h2 className="text-xl font-semibold mb-4 text-slate-800 flex items-center gap-2">
                                <i className="ph-fill ph-camera text-blue-600 text-2xl"></i> Fotos / Evidências do Equipamento
                            </h2>
                            <p className="text-sm text-slate-500 mb-4">Adicione fotos e arraste-as para reordenar (serão incluídas na mesma ordem no final do PDF).</p>

                            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                                ${reportImages.map((img, index) => html`
                                    <div key=${img.id} draggable="true" onDragStart=${(e) => handleDragStart(e, index)} onDragOver=${(e) => handleDragOver(e, index)} onDragLeave=${handleDragLeave} onDrop=${(e) => handleDrop(e, index)}
                                        className=${`relative border rounded p-2 flex flex-col gap-2 group cursor-move transition-all duration-200 ${draggedOverImgIndex === index ? 'border-blue-500 bg-blue-100 scale-105 shadow-lg' : 'border-slate-200 bg-slate-50'} ${draggedImgIndex === index ? 'opacity-40' : 'opacity-100'}`}>
                                        <div className="absolute top-2 left-2 flex gap-1 opacity-0 group-hover:opacity-100 transition z-10 md:hidden print:hidden">
                                            <button onClick=${() => moveImage(index, -1)} disabled=${index === 0} className="bg-slate-800/80 text-white rounded p-1 disabled:opacity-30"><i className="ph-bold ph-caret-left"></i></button>
                                            <button onClick=${() => moveImage(index, 1)} disabled=${index === reportImages.length - 1} className="bg-slate-800/80 text-white rounded p-1 disabled:opacity-30"><i className="ph-bold ph-caret-right"></i></button>
                                        </div>
                                        <button onClick=${() => removeReportImage(img.id)} className="absolute -top-2 -right-2 bg-red-500 hover:bg-red-600 text-white rounded-full p-1 shadow-md opacity-0 group-hover:opacity-100 transition z-10"><i className="ph-bold ph-x"></i></button>
                                        <div className="w-full h-32 bg-white flex items-center justify-center overflow-hidden rounded border border-slate-200 pointer-events-none">
                                            <img src=${img.src} alt="Evidência" className="w-full h-full object-cover" />
                                        </div>
                                        <input type="text" placeholder="Legenda da foto..." value=${img.caption} onChange=${(e) => updateReportImageCaption(img.id, e.target.value)} className="text-xs p-1.5 border border-slate-300 rounded w-full focus:ring-1 focus:ring-blue-500 outline-none" />
                                    </div>
                                `)}
                            </div>

                            <button onClick=${() => setSourceModalOpen(true)} type="button" className="bg-blue-50 text-blue-700 px-4 py-2 rounded-lg font-medium inline-flex items-center gap-2 border border-blue-200 hover:bg-blue-100 transition shadow-sm">
                                <i className="ph-bold ph-camera-plus text-lg"></i> Adicionar Foto / Evidência
                            </button>
                            <input type="file" accept="image/*" capture="environment" ref=${cameraInputRef} onChange=${handleFileSelect} className="hidden" />
                            <input type="file" accept="image/*" multiple ref=${galleryInputRef} onChange=${handleFileSelect} className="hidden" />
                        </div>

                        ${!currentOs && html`
                            <div className="bg-gradient-to-r from-indigo-50 to-blue-50 border-2 border-indigo-200 p-5 rounded-xl flex flex-col md:flex-row items-start md:items-center gap-4">
                                <div className="flex-1">
                                    <h3 className="font-bold text-indigo-900 flex items-center gap-2"><i className="ph-fill ph-clipboard-text text-indigo-600 text-xl"></i> Gerar Ordem de Serviço</h3>
                                    <p className="text-sm text-indigo-700 mt-1">Crie uma OS pré-preenchida com base nos dados deste laudo. Você poderá adicionar serviços e peças, e enviar pro Omie.</p>
                                </div>
                                <button onClick=${generateOsFromCurrentLaudo} className="bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-2.5 rounded-lg font-bold flex items-center gap-2 shadow-md whitespace-nowrap"><i className="ph-bold ph-arrow-right"></i> Gerar OS deste Laudo</button>
                            </div>
                        `}
                        ${currentOs && html`
                            <div className="bg-gradient-to-r from-green-50 to-emerald-50 border-2 border-green-200 p-5 rounded-xl flex flex-col md:flex-row items-start md:items-center gap-4">
                                <div className="flex-1">
                                    <h3 className="font-bold text-green-900 flex items-center gap-2"><i className="ph-fill ph-check-circle text-green-600 text-xl"></i> Laudo Finalizado?</h3>
                                    <p className="text-sm text-green-700 mt-1">Volte pra OS #${currentOs.omieOsNumber || currentOs.id} pra anexar este laudo (PDF + fotos) e atualizar no Omie.</p>
                                </div>
                                <button onClick=${() => setActiveTab('os')} className="bg-green-600 hover:bg-green-700 text-white px-5 py-2.5 rounded-lg font-bold flex items-center gap-2 shadow-md whitespace-nowrap"><i className="ph-bold ph-arrow-right"></i> Voltar pra OS</button>
                            </div>
                        `}

                        <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                            <h2 className="text-xl font-semibold mb-4 text-slate-800 flex items-center gap-2">
                                <i className="ph-fill ph-signature text-blue-600 text-2xl"></i> Assinatura do Técnico
                            </h2>
                            <p className="text-sm text-slate-500 mb-3">A assinatura abaixo aparecerá no campo "Técnico Responsável" do PDF.</p>
                            <${SignaturePad} value=${headerData.technicianSignature || ''} onChange=${(dataUrl) => setHeaderData({...headerData, technicianSignature: dataUrl})} />
                        </div>

                        <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                            <h2 className="text-xl font-semibold mb-4 text-slate-800 flex items-center gap-2">
                                <i className="ph-fill ph-sliders text-indigo-600 text-2xl"></i> Opções do Relatório
                            </h2>
                            <div className="space-y-4">
                                <label className="flex items-center gap-3 cursor-pointer bg-slate-50 p-4 border border-slate-200 rounded-lg">
                                    <input type="checkbox" checked=${headerData.showSignatures !== false} onChange=${e => setHeaderData({...headerData, showSignatures: e.target.checked})} className="w-5 h-5 text-indigo-600 rounded cursor-pointer" />
                                    <span className="font-medium text-slate-700">Incluir bloco de assinaturas no PDF</span>
                                </label>

                                <div className="bg-slate-50 p-4 border border-slate-200 rounded-lg flex flex-col md:flex-row md:items-center gap-4 justify-between">
                                    <div>
                                        <span className="block font-medium text-slate-700">Margem do Documento (PDF)</span>
                                        <span className="text-xs text-slate-500">Ajuste caso o conteúdo esteja cortando na sua impressora.</span>
                                    </div>
                                    <select value=${pdfMargin} onChange=${e => setPdfMargin(e.target.value)} className="p-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none bg-white min-w-[150px]">
                                        <option value="0.5cm">Estreita (0.5cm)</option>
                                        <option value="1.0cm">Normal (1.0cm)</option>
                                        <option value="1.5cm">Padrão (1.5cm)</option>
                                        <option value="2.5cm">Larga (2.5cm)</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            };

            const renderSettings = () => {
                if(!currentEditingModel) return null;

                return html`
                    <div className="space-y-8 animate-in fade-in duration-300">
                        <div className="bg-indigo-50 border border-indigo-200 p-4 rounded-xl flex flex-col md:flex-row items-start md:items-center gap-3 text-indigo-800">
                            <div className="flex items-center gap-3 flex-1">
                                <i className="ph-fill ph-info text-2xl"></i>
                                <div>
                                    <h3 className="font-bold">Aviso Administrativo</h3>
                                    <p className="text-sm">As alterações feitas nesta aba afetam <b>todos os usuários</b> do sistema.</p>
                                </div>
                            </div>
                            <div className="flex gap-2 flex-wrap">
                                <button onClick=${exportConfig} className="bg-indigo-600 hover:bg-indigo-700 text-white px-3 py-2 rounded-lg text-sm font-medium flex items-center gap-1"><i className="ph-bold ph-export"></i> Exportar Backup</button>
                                <label className="cursor-pointer bg-white hover:bg-indigo-50 border border-indigo-300 text-indigo-700 px-3 py-2 rounded-lg text-sm font-medium flex items-center gap-1">
                                    <i className="ph-bold ph-upload"></i> Importar Backup
                                    <input type="file" accept=".json,application/json" onChange=${e => { const f = e.target.files[0]; if (f) importConfig(f); e.target.value=''; }} className="hidden" />
                                </label>
                            </div>
                        </div>

                        <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                            <h2 className="text-xl font-semibold mb-2 text-slate-800 flex items-center gap-2">
                                <i className="ph-fill ph-buildings text-indigo-600 text-2xl"></i> Filiais (Contas Omie)
                            </h2>
                            <p className="text-sm text-slate-500 mb-4">Cada filial usa sua própria conta Omie. Os usuários vinculados a uma filial usam automaticamente as credenciais dela. A <b>Matriz</b> usa as credenciais padrão do servidor se você deixar em branco.</p>
                            <div className="space-y-3 mb-4">
                                ${filiaisList.map(f => html`
                                    <div key=${f.id} className="border border-slate-200 rounded-lg p-3 bg-slate-50 flex flex-col md:flex-row md:items-center gap-3 justify-between">
                                        <div className="flex-1">
                                            <div className="font-bold text-slate-800">${f.nome} <span className="text-xs text-slate-400 font-mono">(${f.id})</span></div>
                                            <div className="text-xs mt-1">
                                                ${f.omieConfigured
                                                    ? html`<span className="text-green-600 font-medium"><i className="ph-fill ph-check-circle"></i> Credenciais Omie próprias configuradas</span>`
                                                    : (f.usaEnvVar
                                                        ? html`<span className="text-amber-600 font-medium"><i className="ph-fill ph-warning"></i> Usando credenciais padrão do servidor</span>`
                                                        : html`<span className="text-red-600 font-medium">Sem credenciais</span>`)}
                                            </div>
                                        </div>
                                        <div className="flex gap-2">
                                            <button onClick=${() => {
                                                const k = prompt('Omie App Key da filial "' + f.nome + '" (deixe vazio pra usar a do servidor):', '');
                                                if (k === null) return;
                                                const s = prompt('Omie App Secret da filial "' + f.nome + '":', '');
                                                if (s === null) return;
                                                salvarFilial({ id: f.id, nome: f.nome, omieAppKey: k, omieAppSecret: s });
                                            }} className="bg-indigo-50 hover:bg-indigo-100 text-indigo-700 px-3 py-1.5 rounded text-sm font-medium border border-indigo-200"><i className="ph-bold ph-key"></i> Credenciais Omie</button>
                                            <button onClick=${() => { const n = prompt('Novo nome da filial:', f.nome); if (n) salvarFilial({ id: f.id, nome: n }); }} className="bg-slate-100 hover:bg-slate-200 text-slate-700 px-3 py-1.5 rounded text-sm font-medium"><i className="ph-bold ph-pencil"></i></button>
                                            ${f.id !== 'matriz' && html`<button onClick=${() => excluirFilial(f.id)} className="bg-red-50 hover:bg-red-100 text-red-700 px-3 py-1.5 rounded text-sm font-medium"><i className="ph-bold ph-trash"></i></button>`}
                                        </div>
                                    </div>
                                `)}
                            </div>
                            <button onClick=${() => { const n = prompt('Nome da nova filial (ex: Filial Cidade X):', ''); if (n) salvarFilial({ nome: n }); }} className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2"><i className="ph-bold ph-plus"></i> Nova Filial</button>
                        </div>

                        <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                            <h2 className="text-xl font-semibold mb-4 text-slate-800 flex items-center gap-2">
                                <i className="ph-fill ph-image text-indigo-600 text-2xl"></i> Logo da Empresa no PDF
                            </h2>
                            <div className="flex items-center gap-6">
                                ${logo ? html`
                                    <div className="relative group">
                                        <img src=${logo} alt="Logo" className="h-20 w-auto object-contain border rounded p-2 bg-slate-50" />
                                        <button onClick=${() => setLogo(null)} className="absolute -top-2 -right-2 bg-red-500 text-white p-1 rounded-full"><i className="ph ph-x"></i></button>
                                    </div>
                                ` : html`
                                    <div className="h-20 w-40 border-2 border-dashed border-slate-300 rounded-lg flex flex-col items-center justify-center text-slate-400">
                                        <span className="text-xs">Nenhuma logo</span>
                                    </div>
                                `}
                                <label className="cursor-pointer bg-indigo-50 text-indigo-700 px-4 py-2 rounded-lg font-medium flex items-center gap-2">
                                    <i className="ph ph-upload-simple"></i> Enviar Logo
                                    <input type="file" accept="image/*" onChange=${handleLogoUpload} className="hidden" />
                                </label>
                            </div>
                        </div>

                        <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                            <div className="flex justify-between items-center mb-4">
                                <h2 className="text-xl font-semibold text-slate-800 flex items-center gap-2"><i className="ph-fill ph-textbox text-indigo-600 text-2xl"></i> Campos de Informações Gerais</h2>
                                <button onClick=${addHeaderField} className="bg-indigo-50 hover:bg-indigo-100 text-indigo-700 px-3 py-1.5 rounded text-sm font-medium flex items-center gap-1 border border-indigo-200 transition"><i className="ph-bold ph-plus"></i> Adicionar Campo</button>
                            </div>

                            <div className="space-y-3">
                                ${headerConfig.map((field, index) => html`
                                    <div key=${field.id} className="p-3 bg-slate-50 border border-slate-200 rounded shadow-sm flex flex-col md:flex-row gap-3 items-start md:items-center">
                                        <div className="bg-slate-300 text-slate-700 w-6 h-6 rounded flex items-center justify-center text-xs font-bold">${index + 1}</div>
                                        <div className="flex-1 w-full grid grid-cols-1 md:grid-cols-2 gap-2">
                                            <input type="text" value=${field.label} onChange=${e => updateHeaderField(field.id, 'label', e.target.value)} className="w-full p-2 text-sm border border-slate-300 rounded focus:ring-1 focus:ring-indigo-500" placeholder="Nome do Campo" />
                                            <select value=${field.type} onChange=${e => updateHeaderField(field.id, 'type', e.target.value)} className="w-full p-2 text-sm border border-slate-300 rounded focus:ring-1 focus:ring-indigo-500 bg-white">
                                                <option value="text">Texto Curto</option>
                                                <option value="textarea">Texto Longo</option>
                                            </select>
                                        </div>
                                        <button onClick=${() => removeHeaderField(field.id)} className="text-red-500 hover:bg-red-50 p-2 rounded"><i className="ph-bold ph-trash text-lg"></i></button>
                                    </div>
                                `)}
                            </div>
                        </div>

                        <div className="bg-slate-800 p-6 rounded-xl shadow-md text-white">
                            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-6">
                                <div>
                                    <h2 className="text-xl font-semibold flex items-center gap-2"><i className="ph-fill ph-folder-notch text-indigo-400 text-2xl"></i> Gerenciar Modelos</h2>
                                </div>
                                <button onClick=${createNewModel} className="bg-indigo-500 hover:bg-indigo-400 text-white px-4 py-2 rounded-lg font-medium flex items-center gap-2 shadow-lg transition-colors whitespace-nowrap"><i className="ph-bold ph-plus"></i> Criar Novo Modelo</button>
                            </div>

                            <div className="flex flex-wrap gap-2 mb-6 p-2 bg-slate-900 rounded-lg">
                                ${models.map(m => html`
                                    <button key=${m.id} onClick=${() => setEditingModelId(m.id)} className=${`px-4 py-2 rounded-md font-medium text-sm flex items-center gap-2 transition-all ${editingModelId === m.id ? 'bg-indigo-600 text-white shadow-md' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'}`}><i className="ph-fill ph-battery-full"></i> ${m.name}</button>
                                `)}
                            </div>

                            <div className="bg-white text-slate-800 rounded-xl border border-slate-200 overflow-hidden">
                                <div className="p-4 bg-slate-50 border-b border-slate-200 flex flex-col md:flex-row justify-between items-center gap-4">
                                    <div className="flex-1 w-full">
                                        <label className="block text-xs font-bold text-slate-500 uppercase mb-1">Nome do Modelo Sendo Editado</label>
                                        <input type="text" value=${currentEditingModel.name} onChange=${e => updateCurrentModel('name', e.target.value)} className="w-full text-lg font-bold p-2 border border-slate-300 rounded focus:ring-2 focus:ring-indigo-500 outline-none" />
                                    </div>
                                    <div className="flex gap-2">
                                        <button onClick=${() => duplicateModel(currentEditingModel.id)} className="bg-slate-200 hover:bg-slate-300 text-slate-700 px-3 py-2 rounded font-medium flex items-center gap-1 text-sm"><i className="ph-bold ph-copy"></i> Duplicar</button>
                                        <button onClick=${() => deleteModel(currentEditingModel.id)} className="bg-red-100 hover:bg-red-200 text-red-700 px-3 py-2 rounded font-medium flex items-center gap-1 text-sm"><i className="ph-bold ph-trash"></i> Excluir</button>
                                    </div>
                                </div>

                                <div className="p-6 space-y-8">
                                    <div>
                                        <div className="flex justify-between items-center mb-4 border-b border-slate-200 pb-2">
                                            <h3 className="font-bold text-lg flex items-center gap-2 text-slate-700"><i className="ph-fill ph-images text-indigo-500"></i> Diagramas Base</h3>
                                            <label className="cursor-pointer bg-indigo-50 hover:bg-indigo-100 text-indigo-700 px-3 py-1.5 rounded text-sm font-medium flex items-center gap-1 border border-indigo-200 transition"><i className="ph-bold ph-upload-simple"></i> Enviar Imagem<input type="file" accept="image/*" onChange=${handleDiagramUpload} className="hidden" /></label>
                                        </div>
                                        ${currentEditingModel.diagrams.length === 0 ? html`
                                            <div className="text-center p-6 bg-slate-50 rounded border border-dashed border-slate-300 text-slate-500">Nenhum diagrama adicionado para este modelo.</div>
                                        ` : html`
                                            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
                                                ${currentEditingModel.diagrams.map(diag => html`
                                                    <div key=${diag.id} className="border border-slate-200 rounded-lg p-2 bg-slate-50 relative group">
                                                        <button onClick=${() => removeDiagram(diag.id)} className="absolute -top-2 -right-2 bg-red-500 text-white rounded-full p-1 opacity-0 group-hover:opacity-100 transition shadow-md z-10"><i className="ph-bold ph-x"></i></button>
                                                        <div className="aspect-square w-full flex items-center justify-center bg-white border border-slate-200 rounded overflow-hidden mb-2"><img src=${diag.imageBase64} alt=${diag.name} className="max-w-full max-h-full object-contain" /></div>
                                                        <input type="text" value=${diag.name} onChange=${e => renameDiagram(diag.id, e.target.value)} className="w-full text-xs p-1 border border-slate-300 rounded text-center" />
                                                    </div>
                                                `)}
                                            </div>
                                        `}
                                    </div>

                                    <div>
                                        <div className="flex justify-between items-center mb-4 border-b border-slate-200 pb-2">
                                            <h3 className="font-bold text-lg flex items-center gap-2 text-slate-700"><i className="ph-fill ph-lightning text-yellow-500"></i> Análise de Células (Tensão)</h3>
                                        </div>
                                        <div className="space-y-3 p-4 bg-slate-50 rounded-lg border border-slate-200 mb-6">
                                            <label className="flex items-center gap-3 cursor-pointer">
                                                <input type="checkbox" checked=${(currentEditingModel.cellAnalysis && currentEditingModel.cellAnalysis.enabled) || false}
                                                    onChange=${e => updateCurrentModel('cellAnalysis', { ...(currentEditingModel.cellAnalysis || {}), enabled: e.target.checked, numCells: (currentEditingModel.cellAnalysis||{}).numCells || 14, maxDropV: (currentEditingModel.cellAnalysis||{}).maxDropV || 0.2 })}
                                                    className="w-5 h-5 text-yellow-500 rounded cursor-pointer" />
                                                <span className="font-semibold text-slate-700">Ativar Análise de Células neste modelo</span>
                                            </label>
                                            ${currentEditingModel.cellAnalysis && currentEditingModel.cellAnalysis.enabled && html`
                                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-slate-200">
                                                    <div>
                                                        <label className="block text-xs font-bold text-slate-500 uppercase mb-1">Nº de Células</label>
                                                        <input type="number" min="1" max="200" value=${currentEditingModel.cellAnalysis.numCells || 14}
                                                            onChange=${e => updateCurrentModel('cellAnalysis', { ...currentEditingModel.cellAnalysis, numCells: parseInt(e.target.value) || 14 })}
                                                            className="w-full p-2 border border-slate-300 rounded focus:ring-2 focus:ring-yellow-400 outline-none font-bold" />
                                                    </div>
                                                    <div>
                                                        <label className="block text-xs font-bold text-slate-500 uppercase mb-1">Voltage Drop Máx. (V)</label>
                                                        <input type="number" min="0.001" step="0.001" value=${currentEditingModel.cellAnalysis.maxDropV || 0.2}
                                                            onChange=${e => updateCurrentModel('cellAnalysis', { ...currentEditingModel.cellAnalysis, maxDropV: parseFloat(e.target.value) || 0.2 })}
                                                            className="w-full p-2 border border-slate-300 rounded focus:ring-2 focus:ring-yellow-400 outline-none font-bold" />
                                                        <p className="text-xs text-slate-400 mt-1">Diferença máx-mín tolerada</p>
                                                    </div>
                                                </div>
                                            `}
                                        </div>
                                    </div>

                                    <div>
                                        <div className="flex justify-between items-center mb-4 border-b border-slate-200 pb-2">
                                            <h3 className="font-bold text-lg flex items-center gap-2 text-slate-700"><i className="ph-fill ph-list-dashes text-indigo-500"></i> Perguntas do Checklist</h3>
                                            <button onClick=${addQuestionToModel} className="bg-indigo-50 hover:bg-indigo-100 text-indigo-700 px-3 py-1.5 rounded text-sm font-medium flex items-center gap-1 border border-indigo-200 transition"><i className="ph-bold ph-plus"></i> Adicionar</button>
                                        </div>
                                        <div className="space-y-3">
                                            ${currentEditingModel.questions.map((item, index) => html`
                                                <div key=${item.id} className="p-3 bg-white border border-slate-200 rounded shadow-sm flex flex-col md:flex-row gap-3 items-start md:items-center">
                                                    <div className="bg-slate-200 text-slate-600 w-6 h-6 rounded flex items-center justify-center text-xs font-bold">${index + 1}</div>
                                                    <div className="flex-1 w-full space-y-2">
                                                        <input type="text" value=${item.label} onChange=${e => updateCurrentModelQuestion(item.id, 'label', e.target.value)} className="w-full p-2 text-sm border border-slate-300 rounded focus:ring-1 focus:ring-indigo-500" placeholder="Título" />
                                                        <div className="flex gap-2">
                                                            <select value=${item.type} onChange=${e => updateCurrentModelQuestion(item.id, 'type', e.target.value)} className="w-1/2 p-2 text-sm border border-slate-300 rounded focus:ring-1 focus:ring-indigo-500 bg-white">
                                                                <option value="checkbox">Selecionar</option>
                                                                <option value="checkbox_qty">Selecionar + Qtd</option>
                                                                <option value="checkbox_text">Selecionar + Texto</option>
                                                                <option value="text">Apenas Texto</option>
                                                            </select>
                                                            ${(item.type === 'checkbox_qty' || item.type === 'checkbox_text') && html`
                                                                <input type="text" value=${item.subLabel || ''} onChange=${e => updateCurrentModelQuestion(item.id, 'subLabel', e.target.value)} className="w-1/2 p-2 text-sm border border-slate-300 rounded focus:ring-1 focus:ring-indigo-500" placeholder="Rótulo extra" />
                                                            `}
                                                        </div>
                                                    </div>
                                                    <button onClick=${() => removeQuestionFromModel(item.id)} className="text-red-500 hover:bg-red-50 p-2 rounded"><i className="ph-bold ph-trash text-lg"></i></button>
                                                </div>
                                            `)}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            };

            const renderUsers = () => {
                const handleAddUser = (e) => {
                    e.preventDefault();
                    const f = e.target;
                    const payload = {
                        username: f.newUser.value,
                        password: f.newPass.value,
                        role: f.newRole.value,
                        firstName: f.firstName.value,
                        lastName: f.lastName.value,
                        email: f.email.value,
                        phone: f.phone.value,
                        filialId: f.filialId ? f.filialId.value : 'matriz'
                    };
                    fetch('/api/users', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'Authorization': auth.token },
                        body: JSON.stringify(payload)
                    }).then(r => r.json()).then(d => {
                        if(d.success) { f.reset(); fetchUsers(); }
                        else alert(d.error || 'Erro ao criar usuário');
                    });
                };

                const handleDeleteUser = (u) => {
                    if(!confirm(`Excluir definitivamente o usuário "${u}"? Esta ação não pode ser desfeita.`)) return;
                    fetch('/api/users', {
                        method: 'DELETE',
                        headers: { 'Content-Type': 'application/json', 'Authorization': auth.token },
                        body: JSON.stringify({ username: u })
                    }).then(r => r.json()).then(d => { if(d.success) fetchUsers(); });
                };

                const callUserAction = (username, action, opts = {}) => {
                    fetch(`/api/users/${encodeURIComponent(username)}/${action}`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'Authorization': auth.token },
                        body: JSON.stringify(opts.body || {})
                    }).then(r => r.json()).then(d => {
                        if (d.success) {
                            if (action === 'reset-password' && d.tempPassword) {
                                setTempPasswordInfo({ username, password: d.tempPassword });
                            }
                            fetchUsers();
                        } else {
                            alert(d.error || 'Erro');
                        }
                    });
                };

                const pending = usersList.filter(u => u.status === 'pending');
                const active = usersList.filter(u => u.status !== 'pending');

                const statusBadge = (s) => {
                    const map = {
                        'active': { c: 'bg-green-100 text-green-700', t: 'Ativo' },
                        'pending': { c: 'bg-amber-100 text-amber-700', t: 'Pendente' },
                        'disabled': { c: 'bg-slate-200 text-slate-500', t: 'Desativado' }
                    };
                    const x = map[s] || map.active;
                    return html`<span className=${`px-2 py-0.5 rounded text-xs font-bold ${x.c}`}>${x.t}</span>`;
                };

                return html`
                    <div className="space-y-6 animate-in fade-in duration-300">
                        ${pending.length > 0 && html`
                            <div className="bg-amber-50 border-2 border-amber-300 p-5 rounded-xl">
                                <h2 className="text-lg font-semibold mb-3 text-amber-900 flex items-center gap-2">
                                    <i className="ph-fill ph-user-circle-plus text-amber-600 text-2xl"></i> Cadastros pendentes de aprovação (${pending.length})
                                </h2>
                                <div className="space-y-3">
                                    ${pending.map(u => html`
                                        <div key=${u.username} className="bg-white border border-amber-200 rounded-lg p-4 flex flex-col md:flex-row md:items-center gap-3 justify-between">
                                            <div className="flex-1">
                                                <div className="font-bold text-slate-800">${u.firstName} ${u.lastName} <span className="text-slate-400 font-normal">(${u.username})</span></div>
                                                <div className="text-xs text-slate-500 mt-1 flex flex-wrap gap-x-3 gap-y-1">
                                                    <span><i className="ph ph-envelope"></i> ${u.email}</span>
                                                    <span><i className="ph ph-phone"></i> ${u.phone}</span>
                                                </div>
                                            </div>
                                            <div className="flex gap-2">
                                                <button onClick=${() => callUserAction(u.username, 'approve')} className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded font-medium text-sm flex items-center gap-1"><i className="ph-bold ph-check"></i> Aprovar</button>
                                                <button onClick=${() => handleDeleteUser(u.username)} className="bg-red-100 hover:bg-red-200 text-red-700 px-4 py-2 rounded font-medium text-sm flex items-center gap-1"><i className="ph-bold ph-x"></i> Rejeitar</button>
                                            </div>
                                        </div>
                                    `)}
                                </div>
                            </div>
                        `}

                        <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                            <h2 className="text-xl font-semibold mb-4 text-slate-800 flex items-center gap-2">
                                <i className="ph-fill ph-user-plus text-blue-600 text-2xl"></i> Criar Usuário Manualmente
                            </h2>
                            <form onSubmit=${handleAddUser} className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                <input name="firstName" required type="text" placeholder="Nome" className="p-2 border border-slate-300 rounded focus:ring-2 focus:ring-blue-500 outline-none" />
                                <input name="lastName" required type="text" placeholder="Sobrenome" className="p-2 border border-slate-300 rounded focus:ring-2 focus:ring-blue-500 outline-none" />
                                <input name="email" type="email" placeholder="E-mail" className="p-2 border border-slate-300 rounded focus:ring-2 focus:ring-blue-500 outline-none" />
                                <input name="phone" type="tel" placeholder="Telefone" className="p-2 border border-slate-300 rounded focus:ring-2 focus:ring-blue-500 outline-none" />
                                <input name="newUser" required type="text" placeholder="Login (nome de usuário)" className="p-2 border border-slate-300 rounded focus:ring-2 focus:ring-blue-500 outline-none" />
                                <input name="newPass" required type="text" minLength="6" placeholder="Senha (min. 6 caracteres)" className="p-2 border border-slate-300 rounded focus:ring-2 focus:ring-blue-500 outline-none" />
                                <select name="newRole" className="p-2 border border-slate-300 rounded focus:ring-2 focus:ring-blue-500 outline-none bg-white">
                                    <option value="user">Usuário Padrão</option>
                                    <option value="admin">Administrador</option>
                                </select>
                                <select name="filialId" className="p-2 border border-slate-300 rounded focus:ring-2 focus:ring-blue-500 outline-none bg-white">
                                    ${filiaisList.map(f => html`<option key=${f.id} value=${f.id}>Filial: ${f.nome}</option>`)}
                                </select>
                                <button type="submit" className="bg-blue-600 text-white px-6 py-2 rounded font-medium hover:bg-blue-700 md:col-span-2">Criar Usuário</button>
                            </form>
                        </div>

                        <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                            <h2 className="text-xl font-semibold mb-4 text-slate-800 flex items-center gap-2">
                                <i className="ph-fill ph-list text-slate-600 text-2xl"></i> Usuários do Sistema (${active.length})
                            </h2>
                            <div className="overflow-x-auto rounded-lg border border-slate-200">
                                <table className="min-w-full text-left text-sm">
                                    <thead className="bg-slate-100 border-b border-slate-200 text-slate-700">
                                        <tr>
                                            <th className="p-3 font-bold">Nome</th>
                                            <th className="p-3 font-bold">Login</th>
                                            <th className="p-3 font-bold">Contato</th>
                                            <th className="p-3 font-bold">Acesso</th>
                                            <th className="p-3 font-bold">Filial</th>
                                            <th className="p-3 font-bold">Status</th>
                                            <th className="p-3 font-bold text-right">Ações</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-slate-100">
                                        ${active.map(u => html`
                                            <tr key=${u.username} className="hover:bg-slate-50">
                                                <td className="p-3 font-medium whitespace-nowrap">${u.firstName} ${u.lastName}${u.username === auth.token ? html` <span className="text-xs text-slate-400 ml-1">(você)</span>` : ''}</td>
                                                <td className="p-3 font-mono text-xs">${u.username}</td>
                                                <td className="p-3 text-xs text-slate-600">
                                                    ${u.email && html`<div><i className="ph ph-envelope"></i> ${u.email}</div>`}
                                                    ${u.phone && html`<div><i className="ph ph-phone"></i> ${u.phone}</div>`}
                                                </td>
                                                <td className="p-3">
                                                    <span className=${`px-2 py-0.5 rounded text-xs font-bold ${u.role==='admin'?'bg-indigo-100 text-indigo-700':'bg-slate-200 text-slate-700'}`}>${u.role.toUpperCase()}</span>
                                                </td>
                                                <td className="p-3">
                                                    <select value=${u.filialId || 'matriz'} onChange=${e => trocarFilialUsuario(u.username, e.target.value)} className="text-xs p-1 border border-slate-300 rounded bg-white">
                                                        ${filiaisList.map(f => html`<option key=${f.id} value=${f.id}>${f.nome}</option>`)}
                                                    </select>
                                                </td>
                                                <td className="p-3">${statusBadge(u.status)}</td>
                                                <td className="p-3 text-right whitespace-nowrap">
                                                    <div className="flex justify-end gap-1 flex-wrap">
                                                        <button title="Resetar senha" onClick=${() => callUserAction(u.username, 'reset-password')} className="text-amber-700 bg-amber-50 hover:bg-amber-100 px-2 py-1 rounded text-xs font-medium"><i className="ph-bold ph-key"></i></button>
                                                        ${u.username !== auth.token && (u.status === 'active' ? html`
                                                            <button title="Desativar" onClick=${() => callUserAction(u.username, 'disable')} className="text-slate-700 bg-slate-100 hover:bg-slate-200 px-2 py-1 rounded text-xs font-medium"><i className="ph-bold ph-pause"></i></button>
                                                        ` : html`
                                                            <button title="Reativar" onClick=${() => callUserAction(u.username, 'enable')} className="text-green-700 bg-green-50 hover:bg-green-100 px-2 py-1 rounded text-xs font-medium"><i className="ph-bold ph-play"></i></button>
                                                        `)}
                                                        ${u.username !== auth.token && html`
                                                            <button title="Excluir" onClick=${() => handleDeleteUser(u.username)} className="text-red-700 bg-red-50 hover:bg-red-100 px-2 py-1 rounded text-xs font-medium"><i className="ph-bold ph-trash"></i></button>
                                                        `}
                                                    </div>
                                                </td>
                                            </tr>
                                        `)}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                `;
            };

            const renderOS = () => {
                // Tela de edição de uma OS específica
                if (currentOs) {
                    const updateOs = (patch) => setCurrentOs(prev => ({ ...prev, ...patch }));
                    const updateService = (i, patch) => updateOs({ services: currentOs.services.map((s, idx) => idx === i ? { ...s, ...patch } : s) });
                    const updatePart = (i, patch) => updateOs({ parts: currentOs.parts.map((p, idx) => idx === i ? { ...p, ...patch } : p) });
                    const addService = () => updateOs({ services: [...(currentOs.services || []), { omieServiceId: null, code: '', description: '', quantity: 1, unitPrice: 0 }] });
                    const removeService = (i) => updateOs({ services: currentOs.services.filter((_, idx) => idx !== i) });
                    const addPart = () => updateOs({ parts: [...(currentOs.parts || []), { omieProductId: null, code: '', description: '', quantity: 1, unitPrice: 0 }] });
                    const removePart = (i) => updateOs({ parts: currentOs.parts.filter((_, idx) => idx !== i) });
                    const isLocked = currentOs.status === 'sent';

                    return html`
                        <div className="space-y-6 animate-in fade-in duration-300">
                            <div className="bg-white p-4 rounded-xl border border-slate-200 flex flex-col md:flex-row md:items-center gap-3 justify-between">
                                <div>
                                    <button onClick=${() => setCurrentOs(null)} className="text-sm text-slate-500 hover:text-slate-700"><i className="ph-bold ph-arrow-left"></i> Voltar para lista</button>
                                    <h2 className="text-xl font-bold text-slate-800 mt-1 flex items-center gap-2">
                                        <i className="ph-fill ph-clipboard-text text-indigo-600 text-2xl"></i>
                                        ${isLocked
                                            ? `OS #${currentOs.omieOsNumber || currentOs.omieOsId} (enviada)`
                                            : (currentOs.status === 'imported'
                                                ? `Editando OS #${currentOs.omieOsNumber || currentOs.omieOsId} (vinda do Omie)`
                                                : 'Editar Rascunho de OS')}
                                    </h2>
                                </div>
                                <div className="flex gap-2 flex-wrap">
                                    <button onClick=${irParaLaudoDesta} className="bg-blue-50 hover:bg-blue-100 text-blue-700 px-4 py-2 rounded font-medium flex items-center gap-1 border border-blue-200">
                                        <i className="ph-bold ph-file-text"></i> Preencher Laudo desta OS
                                    </button>
                                    ${!isLocked && html`
                                        <button onClick=${() => saveCurrentOs(false)} className="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded font-medium flex items-center gap-1"><i className="ph-bold ph-floppy-disk"></i> Salvar</button>
                                        <button onClick=${sendOsToOmie} disabled=${omieStatus.checked && !omieStatus.ok} className=${`px-4 py-2 rounded font-medium flex items-center gap-1 text-white ${(omieStatus.checked && !omieStatus.ok) ? 'bg-slate-400 cursor-not-allowed' : 'bg-green-600 hover:bg-green-700'}`}>
                                            <i className="ph-bold ph-paper-plane-tilt"></i> ${currentOs.status === 'imported' ? 'Atualizar OS no Omie' : 'Enviar pro Omie'}
                                        </button>
                                    `}
                                    ${(isLocked || currentOs.status === 'imported') && currentOs.omieOsId && html`
                                        <button onClick=${anexarLaudoPDF} className=${`px-4 py-2 rounded font-medium flex items-center gap-1 text-white ${currentOs.pdfAnexado ? 'bg-slate-500 hover:bg-slate-600' : 'bg-purple-600 hover:bg-purple-700'}`}>
                                            <i className="ph-bold ph-paperclip"></i> ${currentOs.pdfAnexado ? 'Re-anexar Laudo' : 'Anexar PDF do Laudo'}
                                        </button>
                                        <button onClick=${anexarFotosLaudo} className=${`px-4 py-2 rounded font-medium flex items-center gap-1 text-white ${currentOs.fotosAnexadas ? 'bg-slate-500 hover:bg-slate-600' : 'bg-pink-600 hover:bg-pink-700'}`}>
                                            <i className="ph-bold ph-images"></i> ${currentOs.fotosAnexadas ? `Re-anexar Fotos (${currentOs.fotosCount || 0})` : 'Anexar Fotos (ZIP)'}
                                        </button>
                                    `}
                                    <button onClick=${finalizarCompleto} disabled=${finalizando} className=${`px-4 py-2 rounded-lg font-bold flex items-center gap-2 text-white shadow-md transition ${finalizando ? 'bg-slate-400 cursor-not-allowed' : 'bg-emerald-600 hover:bg-emerald-700'}`}>
                                        ${finalizando
                                            ? html`<i className="ph ph-spinner animate-spin"></i> Enviando...`
                                            : html`<i className="ph-bold ph-check-circle"></i> Finalizar e Enviar Tudo`}
                                    </button>
                                </div>
                            </div>

                            ${osSendError && html`<div className="bg-red-50 border border-red-200 text-red-700 p-3 rounded">${osSendError}</div>`}

                            ${currentOs.fromLaudo && html`
                                <div className="bg-blue-50 border border-blue-200 p-3 rounded-lg text-sm text-blue-800 flex items-center gap-2">
                                    <i className="ph-fill ph-link"></i>
                                    <span>Esta OS foi gerada a partir do laudo de <b>${currentOs.fromLaudo.client || 'cliente'}</b> ${currentOs.fromLaudo.model ? `— ${currentOs.fromLaudo.model}` : ''}</span>
                                </div>
                            `}

                            <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                                <h3 className="text-lg font-semibold mb-3 text-slate-800 flex items-center gap-2"><i className="ph-fill ph-user text-blue-600 text-xl"></i> Cliente</h3>
                                ${currentOs.client && currentOs.client.omieClientId ? html`
                                    <div className="bg-green-50 border border-green-200 p-3 rounded flex justify-between items-center">
                                        <div>
                                            <div className="font-bold text-slate-800">${currentOs.client.name}</div>
                                            <div className="text-xs text-slate-500">Omie ID: ${currentOs.client.omieClientId} ${currentOs.client.document && `| ${currentOs.client.document}`}</div>
                                        </div>
                                        ${!isLocked && html`<button onClick=${() => updateOs({ client: { omieClientId: null, name: currentOs.client.name || '', document: '', email: '', phone: '' } })} className="text-xs bg-white hover:bg-slate-100 border border-slate-300 px-2 py-1 rounded">Trocar</button>`}
                                    </div>
                                ` : html`
                                    <div className="space-y-3">
                                        <div className="flex gap-2">
                                            <input type="text" placeholder="Buscar cliente (use % como atalho, ex: bio%agro)..." value=${clienteSearch} onChange=${(e) => setClienteSearch(e.target.value)} className="flex-1 p-2 border border-slate-300 rounded outline-none focus:ring-2 focus:ring-blue-500" />
                                            <button onClick=${() => searchClientes(clienteSearch)} className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded font-medium"><i className="ph-bold ph-magnifying-glass"></i></button>
                                            <button onClick=${() => setShowNewClienteModal(true)} className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded font-medium" title="Cadastrar novo cliente no Omie"><i className="ph-bold ph-plus"></i></button>
                                        </div>
                                        ${clienteMsg && html`<div className="text-xs text-slate-600 italic">${clienteMsg}</div>`}
                                        ${clienteResults.length > 0 && html`
                                            <div className="border border-slate-200 rounded divide-y divide-slate-100 max-h-60 overflow-y-auto">
                                                ${clienteResults.map(c => html`
                                                    <button key=${c.id} onClick=${() => { updateOs({ client: { omieClientId: c.id, name: c.name, document: c.document, email: c.email, phone: c.phone } }); setClienteResults([]); setClienteSearch(''); setClienteMsg(''); }} className="w-full text-left p-3 hover:bg-blue-50 transition">
                                                        <div className="font-medium">${c.name}</div>
                                                        <div className="text-xs text-slate-500">${c.document || ''} ${c.email ? '| ' + c.email : ''}</div>
                                                    </button>
                                                `)}
                                            </div>
                                        `}
                                        ${currentOs.client && currentOs.client.name && !currentOs.client.omieClientId && html`
                                            <div className="text-xs text-amber-700 bg-amber-50 border border-amber-200 p-2 rounded"><i className="ph-fill ph-warning"></i> Cliente "<b>${currentOs.client.name}</b>" não está cadastrado no Omie. Busque acima ou clique no <b>+</b> pra cadastrar.</div>
                                        `}
                                    </div>
                                `}
                            </div>

                            <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                                <div className="flex justify-between items-center mb-3">
                                    <h3 className="text-lg font-semibold text-slate-800 flex items-center gap-2"><i className="ph-fill ph-wrench text-blue-600 text-xl"></i> Serviços</h3>
                                    ${!isLocked && html`<button onClick=${addService} className="bg-blue-50 hover:bg-blue-100 text-blue-700 px-3 py-1.5 rounded text-sm font-medium border border-blue-200"><i className="ph-bold ph-plus"></i> Adicionar Serviço</button>`}
                                </div>
                                ${(currentOs.services || []).length === 0 ? html`
                                    <div className="text-center text-sm text-slate-400 py-4">Nenhum serviço adicionado.</div>
                                ` : html`
                                    <div className="space-y-2">
                                        ${currentOs.services.map((s, i) => html`
                                            <div key=${i} className="bg-slate-50 border border-slate-200 rounded p-3">
                                                <div className="flex gap-2 items-start">
                                                    <div className="flex-1 space-y-2">
                                                        <div className="flex gap-2">
                                                            <input type="text" placeholder="Buscar serviço (use % como atalho, ex: man%bat%t40)..." value=${servicoSearch.forIndex === i ? servicoSearch.q : (s.description || '')} onChange=${(e) => setServicoSearch({ q: e.target.value, forIndex: i })} className="flex-1 p-2 border border-slate-300 rounded text-sm" disabled=${isLocked} />
                                                            ${!isLocked && html`<button onClick=${() => searchServicos(servicoSearch.forIndex === i ? servicoSearch.q : (s.description || ''))} className="bg-blue-600 text-white px-3 rounded text-sm"><i className="ph-bold ph-magnifying-glass"></i></button>`}
                                                        </div>
                                                        ${servicoSearch.forIndex === i && servicoMsg && html`<div className="text-xs text-slate-600 italic">${servicoMsg}</div>`}
                                                        ${servicoSearch.forIndex === i && servicoResults.length > 0 && html`
                                                            <div className="border border-slate-200 rounded divide-y divide-slate-100 max-h-40 overflow-y-auto bg-white">
                                                                ${servicoResults.map(sr => html`
                                                                    <button key=${sr.id} onClick=${() => { updateService(i, { omieServiceId: sr.id, code: sr.code, description: sr.description, unitPrice: sr.unitPrice || s.unitPrice, cTribServ: sr.cTribServ, cCodServMun: sr.cCodServMun, cCodLC116: sr.cCodLC116, cCodCateg: sr.cCodCateg }); setServicoSearch({ q: '', forIndex: null }); setServicoResults([]); }} className="w-full text-left p-2 text-sm hover:bg-blue-50">
                                                                        <div className="font-medium">${sr.code} — ${sr.description}</div>
                                                                        <div className="text-xs text-slate-500">R$ ${(sr.unitPrice || 0).toFixed(2)}</div>
                                                                    </button>
                                                                `)}
                                                            </div>
                                                        `}
                                                        ${s.omieServiceId ? html`<div className="text-xs text-green-700"><i className="ph-fill ph-check-circle"></i> Vinculado: ${s.code} — ${s.description}</div>` : html`<div className="text-xs text-amber-700"><i className="ph ph-warning"></i> Não vinculado ao Omie</div>`}
                                                        <div className="flex gap-2 items-center">
                                                            <label className="text-xs text-slate-600">Qtd</label>
                                                            <input type="number" min="0" step="0.01" value=${s.quantity} onChange=${e => updateService(i, { quantity: e.target.value })} className="w-20 p-1.5 border border-slate-300 rounded text-sm" disabled=${isLocked} />
                                                            <label className="text-xs text-slate-600 ml-2">R$ unit.</label>
                                                            <input type="number" min="0" step="0.01" value=${s.unitPrice} onChange=${e => updateService(i, { unitPrice: e.target.value })} className="w-24 p-1.5 border border-slate-300 rounded text-sm" disabled=${isLocked} />
                                                            <div className="ml-auto text-sm font-bold text-slate-700">= R$ ${((parseFloat(s.quantity)||0) * (parseFloat(s.unitPrice)||0)).toFixed(2)}</div>
                                                        </div>
                                                    </div>
                                                    ${!isLocked && html`<button onClick=${() => removeService(i)} className="text-red-500 hover:bg-red-50 p-2 rounded"><i className="ph-bold ph-trash"></i></button>`}
                                                </div>
                                            </div>
                                        `)}
                                    </div>
                                `}
                            </div>

                            <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                                <div className="flex justify-between items-center mb-3">
                                    <h3 className="text-lg font-semibold text-slate-800 flex items-center gap-2"><i className="ph-fill ph-package text-blue-600 text-xl"></i> Peças</h3>
                                    ${!isLocked && html`<button onClick=${addPart} className="bg-blue-50 hover:bg-blue-100 text-blue-700 px-3 py-1.5 rounded text-sm font-medium border border-blue-200"><i className="ph-bold ph-plus"></i> Adicionar Peça</button>`}
                                </div>
                                ${(currentOs.parts || []).length === 0 ? html`
                                    <div className="text-center text-sm text-slate-400 py-4">Nenhuma peça adicionada.</div>
                                ` : html`
                                    <div className="space-y-2">
                                        ${currentOs.parts.map((p, i) => html`
                                            <div key=${i} className="bg-slate-50 border border-slate-200 rounded p-3">
                                                <div className="flex gap-2 items-start">
                                                    <div className="flex-1 space-y-2">
                                                        <div className="flex gap-2">
                                                            <input type="text" placeholder="Buscar peça (use % como atalho, ex: placa%princ%t40)..." value=${produtoSearch.forIndex === i ? produtoSearch.q : (p.description || '')} onChange=${(e) => setProdutoSearch({ q: e.target.value, forIndex: i })} className="flex-1 p-2 border border-slate-300 rounded text-sm" disabled=${isLocked} />
                                                            ${!isLocked && html`<button onClick=${() => searchProdutos(produtoSearch.forIndex === i ? produtoSearch.q : (p.description || ''))} className="bg-blue-600 text-white px-3 rounded text-sm"><i className="ph-bold ph-magnifying-glass"></i></button>`}
                                                        </div>
                                                        ${produtoSearch.forIndex === i && produtoMsg && html`<div className="text-xs text-slate-600 italic">${produtoMsg}</div>`}
                                                        ${produtoSearch.forIndex === i && produtoResults.length > 0 && html`
                                                            <div className="border border-slate-200 rounded divide-y divide-slate-100 max-h-40 overflow-y-auto bg-white">
                                                                ${produtoResults.map(pr => html`
                                                                    <button key=${pr.id} onClick=${() => { updatePart(i, { omieProductId: pr.id, code: pr.code, description: pr.description, unitPrice: pr.unitPrice || p.unitPrice }); setProdutoSearch({ q: '', forIndex: null }); setProdutoResults([]); }} className="w-full text-left p-2 text-sm hover:bg-blue-50">
                                                                        <div className="font-medium">${pr.code} — ${pr.description}</div>
                                                                        <div className="text-xs text-slate-500">${pr.unit || ''} | R$ ${(pr.unitPrice || 0).toFixed(2)}</div>
                                                                    </button>
                                                                `)}
                                                            </div>
                                                        `}
                                                        ${p.omieProductId ? html`<div className="text-xs text-green-700"><i className="ph-fill ph-check-circle"></i> Vinculado: ${p.code} — ${p.description}</div>` : html`<div className="text-xs text-amber-700"><i className="ph ph-warning"></i> Não vinculado ao Omie</div>`}
                                                        <div className="flex gap-2 items-center">
                                                            <label className="text-xs text-slate-600">Qtd</label>
                                                            <input type="number" min="0" step="0.01" value=${p.quantity} onChange=${e => updatePart(i, { quantity: e.target.value })} className="w-20 p-1.5 border border-slate-300 rounded text-sm" disabled=${isLocked} />
                                                            <label className="text-xs text-slate-600 ml-2">R$ unit.</label>
                                                            <input type="number" min="0" step="0.01" value=${p.unitPrice} onChange=${e => updatePart(i, { unitPrice: e.target.value })} className="w-24 p-1.5 border border-slate-300 rounded text-sm" disabled=${isLocked} />
                                                            <div className="ml-auto text-sm font-bold text-slate-700">= R$ ${((parseFloat(p.quantity)||0) * (parseFloat(p.unitPrice)||0)).toFixed(2)}</div>
                                                        </div>
                                                    </div>
                                                    ${!isLocked && html`<button onClick=${() => removePart(i)} className="text-red-500 hover:bg-red-50 p-2 rounded"><i className="ph-bold ph-trash"></i></button>`}
                                                </div>
                                            </div>
                                        `)}
                                    </div>
                                `}
                            </div>

                            <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                                <h3 className="text-lg font-semibold mb-3 text-slate-800 flex items-center gap-2"><i className="ph-fill ph-note text-blue-600 text-xl"></i> Observações</h3>
                                <textarea value=${currentOs.observations || ''} onChange=${(e) => updateOs({ observations: e.target.value })} rows="4" disabled=${isLocked} className="w-full p-3 border border-slate-300 rounded outline-none focus:ring-2 focus:ring-blue-500"></textarea>
                                <div className="mt-4 text-right">
                                    <div className="inline-block bg-slate-900 text-white px-6 py-3 rounded-lg">
                                        <div className="text-xs text-slate-300 uppercase">Total da OS</div>
                                        <div className="text-2xl font-bold">R$ ${osTotal(currentOs).toFixed(2)}</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                }

                // Tela de LISTA de OSes
                return html`
                    <div className="space-y-6 animate-in fade-in duration-300">
                        <div className=${`p-4 rounded-xl border flex items-center gap-3 ${omieStatus.ok ? 'bg-green-50 border-green-200' : 'bg-amber-50 border-amber-200'}`}>
                            <i className=${`ph-fill ${omieStatus.ok ? 'ph-check-circle text-green-600' : 'ph-warning text-amber-600'} text-2xl`}></i>
                            <div className="flex-1">
                                <div className="font-bold ${omieStatus.ok ? 'text-green-800' : 'text-amber-800'}">${omieStatus.ok ? 'Conectado ao Omie' : (omieStatus.configured ? 'Erro de conexão Omie' : 'Omie não configurado')}</div>
                                ${!omieStatus.ok && html`<div className="text-sm text-amber-700">${omieStatus.message || 'Cadastre OMIE_APP_KEY e OMIE_APP_SECRET nas variáveis de ambiente do servidor.'}</div>`}
                                ${omieStatus.ok && html`<div className="text-xs text-green-700">Cache em disco persistente (24h). Use "Limpar cache" se cadastrar serviços/peças/clientes novos no Omie.</div>`}
                            </div>
                            <button onClick=${checkOmieStatus} className="text-sm bg-white border border-slate-300 px-3 py-1.5 rounded hover:bg-slate-50" title="Testar conexão"><i className="ph-bold ph-arrows-clockwise"></i> Testar</button>
                            <button onClick=${clearOmieCache} className="text-sm bg-white border border-slate-300 px-3 py-1.5 rounded hover:bg-slate-50" title="Limpa cache local de catálogos do Omie"><i className="ph-bold ph-broom"></i> Limpar cache</button>
                        </div>

                        <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                            <div className="flex justify-between items-center mb-4">
                                <h2 className="text-xl font-semibold text-slate-800 flex items-center gap-2"><i className="ph-fill ph-cloud-arrow-down text-amber-600 text-2xl"></i> OSes Abertas no Omie (${omieAbertas.length})</h2>
                                <button onClick=${fetchOmieAbertas} disabled=${loadingAbertas} className="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded text-sm font-medium flex items-center gap-1 disabled:opacity-50">
                                    <i className=${`ph-bold ph-arrows-clockwise ${loadingAbertas ? 'animate-spin' : ''}`}></i> ${loadingAbertas ? 'Carregando...' : 'Atualizar'}
                                </button>
                            </div>
                            <p className="text-xs text-slate-500 mb-3">OSes criadas no Omie (vendedor) e ainda não faturadas. Clique pra abrir no app, completar dados técnicos e salvar de volta.</p>
                            ${omieAbertas.length === 0 && !loadingAbertas ? html`
                                <div className="text-center py-6 text-sm text-slate-400">Nenhuma OS aberta (não faturada e não cancelada) encontrada nas páginas recentes do Omie.</div>
                            ` : html`
                                <div className="overflow-x-auto rounded border border-slate-200">
                                    <table className="min-w-full text-sm">
                                        <thead className="bg-amber-50 text-slate-700">
                                            <tr>
                                                <th className="p-2 text-left">Nº OS</th>
                                                <th className="p-2 text-left">Cliente</th>
                                                <th className="p-2 text-left">Etapa</th>
                                                <th className="p-2 text-left">Inclusão</th>
                                                <th className="p-2 text-right">Total</th>
                                                <th className="p-2 text-right">Ação</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-slate-100">
                                            ${omieAbertas.map(o => {
                                                const ja = osDrafts.find(d => d.omieOsId === o.nCodOS);
                                                return html`
                                                <tr key=${o.nCodOS} className="hover:bg-slate-50">
                                                    <td className="p-2 font-mono text-xs">${o.cNumOS || '—'}</td>
                                                    <td className="p-2 text-xs">
                                                        <div className="font-medium text-slate-800">${o.clientName || '—'}</div>
                                                        ${o.cContato && html`<div className="text-slate-500">contato: ${o.cContato}</div>`}
                                                    </td>
                                                    <td className="p-2"><span className="bg-amber-100 text-amber-700 px-2 py-0.5 rounded text-xs font-bold">${o.cEtapa || '—'}</span></td>
                                                    <td className="p-2 text-xs">${o.dDtInc || ''}</td>
                                                    <td className="p-2 text-xs text-right">R$ ${parseFloat(o.nValorTotal || 0).toFixed(2)}</td>
                                                    <td className="p-2 text-right">
                                                        ${ja ? html`
                                                            <button onClick=${() => setCurrentOs(ja)} className="bg-blue-50 hover:bg-blue-100 text-blue-700 px-3 py-1 rounded text-xs font-medium">Abrir</button>
                                                        ` : html`
                                                            <button onClick=${() => importarOsDoOmie(o.nCodOS)} className="bg-amber-600 hover:bg-amber-700 text-white px-3 py-1 rounded text-xs font-medium"><i className="ph-bold ph-download-simple"></i> Importar</button>
                                                        `}
                                                    </td>
                                                </tr>
                                            `})}
                                        </tbody>
                                    </table>
                                </div>
                            `}
                        </div>

                        <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                            <div className="flex justify-between items-center mb-4 flex-wrap gap-2">
                                <h2 className="text-xl font-semibold text-slate-800 flex items-center gap-2"><i className="ph-fill ph-clipboard-text text-indigo-600 text-2xl"></i> Ordens de Serviço da Filial</h2>
                                <button onClick=${() => createNewOs()} className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded font-medium flex items-center gap-1"><i className="ph-bold ph-plus"></i> Nova OS</button>
                            </div>
                            ${osDrafts.length === 0 ? html`
                                <div className="text-center py-10 text-slate-500">
                                    <i className="ph ph-clipboard text-5xl"></i>
                                    <p className="mt-2">Nenhuma OS criada ainda. Clique em "Nova OS" ou gere uma a partir de um laudo.</p>
                                </div>
                            ` : html`
                                <div className="flex gap-2 mb-3 text-sm">
                                    ${[['todas','Todas',osDrafts.length],['pendentes','Pendentes',osDrafts.filter(o=>o.status!=='sent').length],['enviadas','Enviadas',osDrafts.filter(o=>o.status==='sent').length]].map(([key,label,count]) => html`
                                        <button key=${key} onClick=${() => setOsFilter(key)} className=${`px-3 py-1.5 rounded-full font-medium border ${osFilter===key ? 'bg-indigo-600 text-white border-indigo-600' : 'bg-white text-slate-600 border-slate-300 hover:bg-slate-50'}`}>${label} <span className=${`ml-1 px-1.5 rounded-full text-xs ${osFilter===key?'bg-white/25':'bg-slate-200 text-slate-700'}`}>${count}</span></button>
                                    `)}
                                </div>
                                <div className="overflow-x-auto">
                                    <table className="min-w-full text-sm">
                                        <thead className="bg-slate-100 text-slate-700">
                                            <tr>
                                                <th className="p-3 text-left">Data</th>
                                                <th className="p-3 text-left">Cliente</th>
                                                <th className="p-3 text-left">Responsável</th>
                                                <th className="p-3 text-center">Itens</th>
                                                <th className="p-3 text-right">Total</th>
                                                <th className="p-3 text-center">Status</th>
                                                <th className="p-3 text-right">Ações</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-slate-100">
                                            ${osDrafts.filter(o => osFilter==='todas' || (osFilter==='enviadas' && o.status==='sent') || (osFilter==='pendentes' && o.status!=='sent')).map(o => html`
                                                <tr key=${o.id} className="hover:bg-slate-50">
                                                    <td className="p-3 text-xs">${new Date(o.createdAt).toLocaleString('pt-BR')}${o.sentAt ? html`<div className="text-green-600">enviada ${new Date(o.sentAt).toLocaleString('pt-BR')}</div>` : ''}</td>
                                                    <td className="p-3">${o.client?.name || '(sem cliente)'}</td>
                                                    <td className="p-3 text-xs text-slate-600">${o.responsavel || '-'}</td>
                                                    <td className="p-3 text-center text-xs">${(o.services||[]).length} serv. / ${(o.parts||[]).length} peças</td>
                                                    <td className="p-3 text-right font-bold">R$ ${osTotal(o).toFixed(2)}</td>
                                                    <td className="p-3 text-center">
                                                        ${o.status === 'sent' ? html`<span className="bg-green-100 text-green-700 px-2 py-0.5 rounded text-xs font-bold">ENVIADA #${o.omieOsNumber || o.omieOsId}</span>` :
                                                          o.sendError ? html`<span className="bg-red-100 text-red-700 px-2 py-0.5 rounded text-xs font-bold" title=${o.sendError}>ERRO</span>` :
                                                          html`<span className="bg-amber-100 text-amber-700 px-2 py-0.5 rounded text-xs font-bold">PENDENTE</span>`}
                                                        ${o.omieStatus ? html`<div className=${`mt-1 text-xs font-bold rounded px-2 py-0.5 inline-block ${o.omieStatus === 'faturada' ? 'bg-emerald-100 text-emerald-700' : (o.omieStatus === 'cancelada' || o.omieStatus === 'excluida') ? 'bg-red-100 text-red-700' : 'bg-blue-100 text-blue-700'}`} title=${o.omieEventAt ? 'Omie em ' + new Date(o.omieEventAt).toLocaleString('pt-BR') : ''}>Omie: ${o.omieStatus}</div>` : ''}
                                                    </td>
                                                    <td className="p-3 text-right whitespace-nowrap">
                                                        <button onClick=${() => setCurrentOs(o)} className="bg-blue-50 hover:bg-blue-100 text-blue-700 px-2 py-1 rounded text-xs font-medium mr-1">${o.status === 'sent' ? 'Ver' : 'Editar'}</button>
                                                        ${o.status !== 'sent' && html`<button onClick=${() => deleteOs(o.id)} className="bg-red-50 hover:bg-red-100 text-red-700 px-2 py-1 rounded text-xs font-medium"><i className="ph-bold ph-trash"></i></button>`}
                                                    </td>
                                                </tr>
                                            `)}
                                        </tbody>
                                    </table>
                                </div>
                            `}
                        </div>
                    </div>
                `;
            };

            const renderPrintView = () => {
                const selectedModel = models.find(m => m.id === headerData.selectedTemplateId);
                const printQuestions = selectedModel ? selectedModel.questions : [];
                const printDiagrams = selectedModel ? selectedModel.diagrams : [];

                return html`
                    <div className="hidden print:block w-full text-black font-sans text-sm relative">
                        <style>${`@media print { body { margin: ${pdfMargin} !important; } }`}</style>
                        <div className="flex justify-between items-center border-b-2 border-black pb-4 mb-6">
                            <div>${logo ? html`<img src=${logo} className="max-h-16 object-contain" />` : html`<div className="text-xl font-bold">LAUDO TÉCNICO</div>`}</div>
                            <div className="text-right">
                                <h1 className="text-2xl font-bold uppercase mb-1">Relatório de Inspeção</h1>
                                <p className="text-xs text-gray-600">Ref: ${selectedModel?.name} | Data: ${new Date(headerData.date).toLocaleDateString('pt-BR')} | Téc: ${auth.token}</p>
                            </div>
                        </div>

                        <div className="mb-6">
                            <h3 className="font-bold uppercase bg-gray-200 p-1.5 mb-2 text-xs border border-gray-300">Informações Gerais</h3>
                            <table className="w-full text-xs border-collapse">
                                <tbody>
                                    ${headerConfig.map(field => html`
                                        <tr key=${field.id}>
                                            <td className="border border-gray-300 p-1.5 font-semibold w-1/3 bg-gray-50">${field.label}:</td>
                                            <td className="border border-gray-300 p-1.5 w-2/3 whitespace-pre-wrap">${headerData[field.id] || '-'}</td>
                                        </tr>
                                    `)}
                                </tbody>
                            </table>
                        </div>

                        ${printQuestions.length > 0 && html`
                            <div className="mb-8">
                                <h3 className="font-bold uppercase bg-gray-200 p-1.5 mb-2 text-xs border border-gray-300">Resultados da Inspeção Física</h3>
                                <table className="w-full text-xs border-collapse">
                                    <thead>
                                        <tr className="bg-gray-100"><th className="border p-1.5 text-left w-3/4">Item Avaliado</th><th className="border p-1.5 text-center w-1/4">Situação / Diagnóstico</th></tr>
                                    </thead>
                                    <tbody>
                                        ${printQuestions.map(item => {
                                            const ans = answers[item.id];
                                            const isChecked = ans?.checked;
                                            let status = 'OK / Normal'; let anormal = false;
                                            if (item.type === 'text') { status = ans?.text || '-'; anormal = !!ans?.text; }
                                            else if (isChecked) { anormal = true; status = item.type === 'checkbox_qty' ? `${ans?.qty || '-'} unid.` : (item.type === 'checkbox_text' ? ans?.text || 'Constatado' : 'Constatado'); }
                                            else { status = 'Não Constatado'; }

                                            return html`
                                                <tr key=${item.id}>
                                                    <td className=${`border p-1.5 ${anormal ? 'font-medium' : 'text-gray-600'}`}>${item.label}</td>
                                                    <td className=${`border p-1.5 text-center ${anormal ? 'font-bold' : 'text-gray-500'}`}>${status}</td>
                                                </tr>
                                            `;
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        `}

                        ${printDiagrams.length > 0 && html`
                            <div className="mb-6 prevent-break">
                                <h3 className="font-bold uppercase bg-gray-200 p-1.5 mb-1 text-xs border border-gray-300">Mapeamento Visual</h3>
                                <div className="grid grid-cols-2 gap-4">${printDiagrams.map(diag => html`<${DiagramRenderer} key=${diag.id} diagram=${diag} isPrintView=${true} />`)}</div>
                            </div>
                        `}

                        ${reportImages.length > 0 && html`
                            <div className="mb-6 prevent-break">
                                <h3 className="font-bold uppercase bg-gray-200 p-1.5 mb-3 text-xs border border-gray-300">Evidências Fotográficas</h3>
                                <div className="grid grid-cols-2 gap-4">
                                    ${reportImages.map(img => html`
                                        <div key=${img.id} className="text-center break-inside-avoid border border-gray-200 p-1 pb-2">
                                            <div className="w-full h-48 flex items-center justify-center bg-white mb-1 overflow-hidden"><img src=${img.src} className="max-w-full max-h-full object-contain" /></div>
                                            <p className="text-xs text-gray-800 font-medium">${img.caption || 'Sem legenda'}</p>
                                        </div>
                                    `)}
                                </div>
                            </div>
                        `}

                        ${headerData.showSignatures !== false && html`
                            <div className="mt-16 flex justify-center px-10 prevent-break">
                                <div className="text-center w-64 relative">
                                    ${headerData.technicianSignature && html`
                                        <img src=${headerData.technicianSignature} alt="Assinatura" style=${{ height: '60px', objectFit: 'contain', margin: '0 auto', display: 'block', marginBottom: '-10px' }} />
                                    `}
                                    <div className="border-t border-black pt-2 font-semibold">Técnico Responsável</div>
                                </div>
                            </div>
                        `}
                    </div>
                `;
            };

            return html`
                <div className="min-h-screen">
                    ${renderPrintView()}
                    <div className="print:hidden max-w-5xl mx-auto p-4 md:p-6 pb-24">
                        <header className="mb-6 flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 text-white p-4 md:p-6 rounded-2xl shadow-lg">
                            <div className="flex items-center gap-4">
                                ${logo
                                    ? html`<img src=${logo} alt="BioDron" className="h-12 w-auto object-contain flex-shrink-0" />`
                                    : html`<i className="ph-fill ph-device-mobile text-blue-400 text-4xl flex-shrink-0"></i>`}
                                <div className="flex flex-col">
                                    <h1 className="text-2xl font-bold">Biodron Smart Report Pro</h1>
                                    <span className="text-slate-400 text-sm mt-0.5 flex items-center gap-2">
                                        <i className="ph-fill ph-user-circle"></i> Olá, <b className="text-white">${auth.username || auth.firstName || 'usuário'}</b>
                                        <button onClick=${handleLogout} className="ml-2 text-red-400 hover:text-red-300 underline font-medium text-xs">Sair da Conta</button>
                                    </span>
                                </div>
                            </div>
                            <div className="flex gap-2 flex-wrap">
                                <button onClick=${gerarTextoIA} className="px-3 py-2 bg-gradient-to-r from-purple-600 to-fuchsia-600 rounded-lg text-sm font-medium hover:from-purple-500 hover:to-fuchsia-500 transition flex items-center gap-1 shadow-md"><i className="ph-bold ph-sparkle"></i> Laudo IA</button>
                                <button onClick=${() => setLaudosModalOpen(true)} className="px-3 py-2 bg-slate-700 rounded-lg text-sm font-medium hover:bg-slate-600 transition flex items-center gap-1"><i className="ph-bold ph-archive"></i> Laudos</button>
                                <button onClick=${downloadImagesZip} className="px-3 py-2 bg-slate-700 rounded-lg text-sm font-medium hover:bg-slate-600 transition flex items-center gap-1" title="Baixar fotos do laudo atual em ZIP"><i className="ph-bold ph-download-simple"></i> Fotos ZIP</button>
                                <button onClick=${clearCurrentReport} className="px-3 py-2 bg-slate-800 rounded-lg text-sm font-medium hover:bg-slate-700 transition">Limpar</button>
                                <button onClick=${baixarPdfLaudo} className="px-3 py-2 bg-blue-600 rounded-lg font-medium flex items-center gap-1 hover:bg-blue-500 transition shadow-md"><i className="ph-bold ph-file-pdf"></i> Gerar PDF</button>
                            </div>
                        </header>

                        <div className="flex space-x-1 mb-6 bg-slate-200 p-1 rounded-xl w-full md:w-fit overflow-x-auto scrollbar-hide">
                            <button onClick=${() => setActiveTab('report')} className=${`whitespace-nowrap px-6 py-2.5 rounded-lg text-sm font-medium flex items-center gap-2 transition-all ${activeTab === 'report' ? 'bg-white text-blue-700 shadow' : 'text-slate-600 hover:bg-slate-300'}`}><i className="ph-bold ph-file-text"></i> Preencher Laudo</button>
                            <button onClick=${() => { setActiveTab('os'); setCurrentOs(null); }} className=${`whitespace-nowrap px-6 py-2.5 rounded-lg text-sm font-medium flex items-center gap-2 transition-all ${activeTab === 'os' ? 'bg-white text-indigo-700 shadow' : 'text-slate-600 hover:bg-slate-300'}`}><i className="ph-bold ph-clipboard-text"></i> Ordens de Serviço</button>

                            ${auth.role === 'admin' && html`
                                <button onClick=${() => setActiveTab('settings')} className=${`whitespace-nowrap px-6 py-2.5 rounded-lg text-sm font-medium flex items-center gap-2 transition-all ${activeTab === 'settings' ? 'bg-white text-indigo-700 shadow' : 'text-slate-600 hover:bg-slate-300'}`}><i className="ph-bold ph-gear"></i> Templates (Global)</button>
                                <button onClick=${() => setActiveTab('users')} className=${`whitespace-nowrap px-6 py-2.5 rounded-lg text-sm font-medium flex items-center gap-2 transition-all ${activeTab === 'users' ? 'bg-white text-emerald-700 shadow' : 'text-slate-600 hover:bg-slate-300'}`}><i className="ph-bold ph-users"></i> Usuários</button>
                            `}
                        </div>

                        <main>
                            ${activeTab === 'report' ? renderReportForm() : ''}
                            ${activeTab === 'os' ? renderOS() : ''}
                            ${activeTab === 'settings' && auth.role === 'admin' ? renderSettings() : ''}
                            ${activeTab === 'users' && auth.role === 'admin' ? renderUsers() : ''}
                        </main>
                    </div>

                    <div className="print:hidden fixed bottom-4 right-4 bg-slate-800 text-white text-xs px-4 py-2 rounded-full shadow-lg flex items-center gap-2 opacity-90 transition-all z-50">
                        ${isSaving ? html`<span className="flex items-center gap-1"><i className="ph ph-spinner animate-spin"></i> Sincronizando...</span>` : html`<span className="flex items-center gap-1"><i className="ph-fill ph-check-circle text-green-400"></i> Salvo na Nuvem</span>`}
                    </div>

                    ${sourceModalOpen && html`
                        <div className="print:hidden fixed inset-0 bg-slate-900/60 z-[60] flex items-end md:items-center justify-center p-4">
                            <div className="bg-white rounded-t-2xl md:rounded-xl shadow-2xl w-full max-w-sm overflow-hidden animate-in slide-in-from-bottom-8 md:zoom-in-95 duration-200">
                                <div className="p-4 bg-slate-50 border-b border-slate-200"><h3 className="font-bold text-lg text-slate-800 text-center">Adicionar Evidência</h3></div>
                                <div className="p-4 space-y-3">
                                    <button onClick=${() => cameraInputRef.current.click()} className="w-full flex items-center justify-center gap-3 bg-blue-600 hover:bg-blue-700 text-white p-4 rounded-xl font-medium transition shadow-sm"><i className="ph-fill ph-camera text-2xl"></i> Tirar Foto (Câmera)</button>
                                    <button onClick=${() => galleryInputRef.current.click()} className="w-full flex items-center justify-center gap-3 bg-slate-100 hover:bg-slate-200 border border-slate-300 text-slate-700 p-4 rounded-xl font-medium transition"><i className="ph-fill ph-image text-2xl"></i> Importar da Galeria</button>
                                    <button onClick=${() => setSourceModalOpen(false)} className="w-full mt-2 p-3 text-red-500 font-medium hover:bg-red-50 rounded-xl transition">Cancelar</button>
                                </div>
                            </div>
                        </div>
                    `}

                    ${iaModalOpen && html`
                        <div className="print:hidden fixed inset-0 bg-slate-900/70 z-[70] flex items-end md:items-center justify-center p-4">
                            <div className="bg-white rounded-t-2xl md:rounded-xl shadow-2xl w-full max-w-2xl max-h-[90vh] flex flex-col">
                                <div className="p-4 bg-gradient-to-r from-purple-600 to-fuchsia-600 text-white flex items-center justify-between rounded-t-2xl md:rounded-t-xl">
                                    <h3 className="font-bold text-lg flex items-center gap-2"><i className="ph-fill ph-sparkle"></i> Laudo elaborado por IA</h3>
                                    <button onClick=${() => setIaModalOpen(false)} className="text-purple-200 hover:text-white"><i className="ph-bold ph-x text-xl"></i></button>
                                </div>
                                <div className="p-4 overflow-y-auto flex-1">
                                    ${iaLoading ? html`
                                        <div className="flex flex-col items-center justify-center py-12 text-slate-500">
                                            <i className="ph ph-spinner animate-spin text-4xl mb-3"></i>
                                            <p>Elaborando o laudo com base nos defeitos encontrados...</p>
                                            <p className="text-xs mt-1">Pode levar até 30 segundos.</p>
                                        </div>
                                    ` : html`
                                        <textarea value=${iaTexto} onChange=${e => setIaTexto(e.target.value)} rows="16" className="w-full p-3 border border-slate-300 rounded-lg text-sm leading-relaxed focus:ring-2 focus:ring-purple-500 outline-none" placeholder="O texto gerado aparecerá aqui..."></textarea>
                                        <p className="text-xs text-slate-400 mt-2">Você pode editar o texto antes de copiar. A IA pode cometer erros — revise sempre.</p>
                                    `}
                                </div>
                                ${!iaLoading && html`
                                    <div className="p-4 border-t border-slate-200 flex gap-2 bg-slate-50 rounded-b-xl">
                                        <button onClick=${gerarTextoIA} className="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-lg font-medium text-sm flex items-center gap-2"><i className="ph-bold ph-arrows-clockwise"></i> Gerar Novamente</button>
                                        <button onClick=${copiarTextoIA} className="flex-1 bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg font-bold text-sm flex items-center justify-center gap-2"><i className="ph-bold ph-copy"></i> Copiar Texto</button>
                                    </div>
                                `}
                            </div>
                        </div>
                    `}

                    ${laudosModalOpen && html`
                        <div className="print:hidden fixed inset-0 bg-slate-900/70 z-[60] flex items-end md:items-center justify-center p-4">
                            <div className="bg-white rounded-t-2xl md:rounded-xl shadow-2xl w-full max-w-lg max-h-[90vh] flex flex-col">
                                <div className="p-4 bg-slate-800 text-white flex items-center justify-between rounded-t-2xl md:rounded-t-xl">
                                    <h3 className="font-bold text-lg flex items-center gap-2"><i className="ph-fill ph-archive"></i> Laudos Salvos</h3>
                                    <button onClick=${() => setLaudosModalOpen(false)} className="text-slate-400 hover:text-white"><i className="ph-bold ph-x text-xl"></i></button>
                                </div>
                                <div className="p-4 border-b border-slate-200 flex gap-2 flex-wrap">
                                    <button onClick=${() => { const clientField = headerConfig.find(f => f.id === 'client'); const cli = clientField ? (headerData[clientField.id] || '') : ''; const sug = cli ? `${cli} — ${headerData.date||''}` : ('Laudo ' + new Date().toLocaleDateString('pt-BR')); const n = prompt('Nome do laudo:', sug); if (n !== null) saveLaudo(n || sug); }} className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg font-medium text-sm flex items-center gap-2"><i className="ph-bold ph-floppy-disk"></i> Salvar Laudo Atual</button>
                                    <button onClick=${clearCurrentReport} className="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-lg font-medium text-sm flex items-center gap-2"><i className="ph-bold ph-plus"></i> Novo Laudo</button>
                                </div>
                                <div className="overflow-y-auto flex-1">
                                    ${laudosList.length === 0 ? html`
                                        <div className="p-8 text-center text-slate-400">
                                            <i className="ph ph-archive text-4xl mb-2 block"></i>
                                            <p>Nenhum laudo salvo ainda.</p>
                                            <p className="text-xs mt-1">Preencha o laudo e clique em "Salvar Laudo Atual".</p>
                                        </div>
                                    ` : laudosList.map(l => html`
                                        <div key=${l.id} className="flex items-center gap-3 p-4 border-b border-slate-100 hover:bg-slate-50">
                                            <div className="flex-1 min-w-0">
                                                <p className="font-semibold text-slate-800 truncate">${l.name}</p>
                                                <p className="text-xs text-slate-400">${l.date ? new Date(l.date).toLocaleDateString('pt-BR') : '—'}</p>
                                            </div>
                                            <div className="flex gap-1 shrink-0">
                                                <button onClick=${() => loadLaudo(l.id)} className="bg-blue-50 hover:bg-blue-100 text-blue-700 px-3 py-1.5 rounded text-xs font-medium" title="Carregar"><i className="ph-bold ph-folder-open"></i></button>
                                                <button onClick=${() => duplicateLaudo(l.id)} className="bg-slate-100 hover:bg-slate-200 text-slate-600 px-3 py-1.5 rounded text-xs font-medium" title="Duplicar"><i className="ph-bold ph-copy"></i></button>
                                                <button onClick=${() => { if(confirm('Excluir o laudo "' + l.name + '"?')) deleteLaudo(l.id); }} className="bg-red-50 hover:bg-red-100 text-red-600 px-3 py-1.5 rounded text-xs font-medium" title="Excluir"><i className="ph-bold ph-trash"></i></button>
                                            </div>
                                        </div>
                                    `)}
                                </div>
                                <div className="p-3 border-t border-slate-200 bg-slate-50 text-xs text-slate-400 text-center rounded-b-xl">
                                    ${laudosList.length} laudo(s) salvos
                                </div>
                            </div>
                        </div>
                    `}

                    ${showNewClienteModal && html`
                        <div className="print:hidden fixed inset-0 bg-slate-900/70 z-[80] flex items-center justify-center p-4">
                            <div className="bg-white rounded-xl shadow-2xl w-full max-w-md p-6">
                                <h3 className="text-lg font-bold text-slate-800 mb-3 flex items-center gap-2"><i className="ph-fill ph-user-plus text-green-600"></i> Novo cliente no Omie</h3>
                                <form onSubmit=${(e) => {
                                    e.preventDefault();
                                    const f = e.target;
                                    createOmieCliente({
                                        name: f.name.value,
                                        document: f.document.value,
                                        email: f.email.value,
                                        phone: f.phone.value
                                    }).then(r => {
                                        if (r.success) {
                                            setCurrentOs(prev => ({ ...prev, client: { omieClientId: r.id, name: f.name.value, document: f.document.value, email: f.email.value, phone: f.phone.value } }));
                                            setShowNewClienteModal(false);
                                        } else {
                                            alert(r.error || 'Erro ao cadastrar');
                                        }
                                    });
                                }} className="space-y-3">
                                    <input name="name" required defaultValue=${currentOs?.client?.name || ''} placeholder="Razão Social / Nome *" className="w-full p-2 border border-slate-300 rounded" />
                                    <input name="document" placeholder="CPF/CNPJ" className="w-full p-2 border border-slate-300 rounded" />
                                    <input name="email" type="email" placeholder="E-mail" className="w-full p-2 border border-slate-300 rounded" />
                                    <input name="phone" placeholder="Telefone" className="w-full p-2 border border-slate-300 rounded" />
                                    <div className="flex gap-2 mt-4">
                                        <button type="button" onClick=${() => setShowNewClienteModal(false)} className="flex-1 bg-slate-100 hover:bg-slate-200 text-slate-700 p-3 rounded font-medium">Cancelar</button>
                                        <button type="submit" className="flex-1 bg-green-600 hover:bg-green-700 text-white p-3 rounded font-bold">Cadastrar no Omie</button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    `}

                    ${tempPasswordInfo && html`
                        <div className="print:hidden fixed inset-0 bg-slate-900/80 z-[80] flex items-center justify-center p-4">
                            <div className="bg-white rounded-xl shadow-2xl w-full max-w-md p-6">
                                <div className="text-center mb-4">
                                    <i className="ph-fill ph-key text-amber-500 text-5xl"></i>
                                    <h3 className="text-xl font-bold text-slate-800 mt-2">Senha Temporária Gerada</h3>
                                    <p className="text-sm text-slate-500">Repasse para <b>${tempPasswordInfo.username}</b>. Esta senha aparece só uma vez.</p>
                                </div>
                                <div className="bg-slate-100 border-2 border-dashed border-slate-300 p-4 rounded-lg text-center mb-4">
                                    <code className="text-2xl font-mono font-bold text-slate-800 tracking-wider select-all">${tempPasswordInfo.password}</code>
                                </div>
                                <p className="text-xs text-slate-500 mb-4 bg-amber-50 border border-amber-200 p-2 rounded"><i className="ph-fill ph-info text-amber-600"></i> No próximo login, o usuário será forçado a definir uma nova senha.</p>
                                <div className="flex gap-2">
                                    <button onClick=${() => { navigator.clipboard?.writeText(tempPasswordInfo.password); }} className="flex-1 bg-slate-100 hover:bg-slate-200 text-slate-700 p-3 rounded-lg font-medium"><i className="ph ph-copy"></i> Copiar</button>
                                    <button onClick=${() => setTempPasswordInfo(null)} className="flex-1 bg-blue-600 hover:bg-blue-700 text-white p-3 rounded-lg font-medium">Fechar</button>
                                </div>
                            </div>
                        </div>
                    `}

                    ${pendingImages.length > 0 && html`
                        <div className="print:hidden fixed inset-0 bg-slate-900/80 z-[70] flex items-center justify-center p-4">
                            <div className="bg-white rounded-xl shadow-2xl w-full max-w-md max-h-[90vh] flex flex-col animate-in zoom-in-95 duration-200">
                                <div className="p-4 bg-indigo-50 border-b border-indigo-100">
                                    <h3 className="font-bold text-lg text-indigo-900 flex items-center gap-2 justify-center"><i className="ph-fill ph-tag"></i> Identificar Foto(s)</h3>
                                    <p className="text-xs text-center text-indigo-600 mt-1">Dê um nome ou descreva o defeito nas imagens abaixo</p>
                                </div>
                                <div className="p-4 overflow-y-auto space-y-4 bg-slate-50">
                                    ${pendingImages.map((img, idx) => html`
                                        <div key=${img.id} className="flex gap-4 items-center bg-white p-3 rounded-lg border border-slate-200 shadow-sm">
                                            <div className="w-20 h-20 shrink-0 bg-slate-100 rounded border border-slate-200 overflow-hidden"><img src=${img.src} alt="Preview" className="w-full h-full object-cover" /></div>
                                            <div className="flex-1">
                                                <label className="block text-xs font-bold text-slate-500 uppercase mb-1">Legenda ${pendingImages.length > 1 ? `(${idx + 1}/${pendingImages.length})` : ''}</label>
                                                <input autoFocus=${idx === 0} type="text" placeholder="Ex: Conector derretido" value=${img.caption}
                                                    onChange=${(e) => { const newPending = [...pendingImages]; newPending[idx].caption = e.target.value; setPendingImages(newPending); }}
                                                    className="w-full p-2 text-sm border border-slate-300 rounded focus:ring-2 focus:ring-blue-500 outline-none" />
                                            </div>
                                        </div>
                                    `)}
                                </div>
                                <div className="p-4 border-t border-slate-200 flex gap-3 bg-white rounded-b-xl">
                                    <button onClick=${() => setPendingImages([])} className="flex-1 bg-slate-100 hover:bg-slate-200 text-slate-600 p-3 rounded-lg font-medium transition">Cancelar</button>
                                    <button onClick=${confirmPendingImages} className="flex-[2] bg-green-600 hover:bg-green-700 text-white p-3 rounded-lg font-bold transition flex justify-center items-center gap-2 shadow-md"><i className="ph-bold ph-check"></i> Adicionar</button>
                                </div>
                            </div>
                        </div>
                    `}
                </div>
            `;
        };

        const root = ReactDOM.createRoot(document.getElementById('root'));
        root.render(html`<${App} />`);
    </script>
</body>
</html>
"""


@app.route('/')
def index():
    return HTML_PAGE


# ==========================================================
#  PWA — app instalável (manifest + service worker + ícones)
# ==========================================================
_ICON_CACHE = {}


def _icon_png(size):
    if size in _ICON_CACHE:
        return _ICON_CACHE[size]
    from PIL import Image, ImageDraw
    S = size
    img = Image.new('RGB', (S, S), (30, 64, 175))  # #1e40af (azul Biodron)
    d = ImageDraw.Draw(img)
    # Corpo da bateria (branco, arredondado)
    bx0, by0, bx1, by1 = int(0.20 * S), int(0.36 * S), int(0.72 * S), int(0.64 * S)
    d.rounded_rectangle([bx0, by0, bx1, by1], radius=int(0.05 * S), fill=(255, 255, 255))
    # Terminal (+)
    d.rounded_rectangle([bx1, int(0.45 * S), int(0.78 * S), int(0.55 * S)], radius=int(0.02 * S), fill=(255, 255, 255))
    # 3 barras de carga (azul) dentro do corpo
    pad = int(0.025 * S)
    inner_w = (bx1 - bx0) - 2 * pad
    bar_w = int((inner_w - 2 * pad) / 3)
    for i in range(3):
        x0 = bx0 + pad + i * (bar_w + pad)
        d.rounded_rectangle([x0, by0 + pad, x0 + bar_w, by1 - pad], radius=int(0.01 * S), fill=(30, 64, 175))
    out = io.BytesIO()
    img.save(out, format='PNG')
    _ICON_CACHE[size] = out.getvalue()
    return _ICON_CACHE[size]


@app.route('/manifest.webmanifest')
def pwa_manifest():
    manifest = {
        "name": "Biodron Smart Report Pro",
        "short_name": "Smart Report",
        "description": "Laudos de bateria DJI Agras e ordens de serviço",
        "start_url": "/",
        "scope": "/",
        "display": "standalone",
        "orientation": "portrait",
        "background_color": "#0f172a",
        "theme_color": "#1e40af",
        "lang": "pt-BR",
        "icons": [
            {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any maskable"},
            {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"}
        ]
    }
    return Response(json.dumps(manifest), mimetype='application/manifest+json')


_SW_JS = """
const CACHE = 'smart-report-v1';
self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.add('/')).catch(()=>{}).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.pathname.startsWith('/api/')) return;            // API sempre na rede
  if (req.mode === 'navigate') {                            // navegação: rede primeiro, cache de reserva
    e.respondWith(
      fetch(req).then((res) => { const cl = res.clone(); caches.open(CACHE).then((c) => c.put('/', cl)); return res; })
                .catch(() => caches.match('/'))
    );
  }
});
"""


@app.route('/sw.js')
def pwa_sw():
    return Response(_SW_JS, mimetype='application/javascript')


@app.route('/icon-192.png')
def pwa_icon_192():
    return Response(_icon_png(192), mimetype='image/png')


@app.route('/icon-512.png')
def pwa_icon_512():
    return Response(_icon_png(512), mimetype='image/png')


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except:
        return "127.0.0.1"
    finally:
        s.close()


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5001))
    ip_local = get_local_ip()
    print("\n" + "=" * 50)
    print("🚀 SERVIDOR BIODRON SMART REPORT PRO (MULTI-USER) INICIADO!")
    print("=" * 50)
    print(f"👉 Acessar no PC: http://localhost:{port}")
    print(f"📱 Acessar no CELULAR: http://{ip_local}:{port}")
    print("=" * 50)
    print("🔐 LOGIN PADRÃO (Admin):")
    print("👤 Usuário: admin")
    print("🔑 Senha: admin")
    print("=" * 50 + "\n")

    app.run(host='0.0.0.0', port=port, debug=False)
