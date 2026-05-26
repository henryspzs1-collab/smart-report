from flask import Flask, jsonify, request
import json
import os
import socket
import re
import secrets
import string
from datetime import datetime
import bcrypt

app = Flask(__name__)


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
        "createdAt": user.get("createdAt", "")
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
        "createdAt": datetime.utcnow().isoformat() + "Z"
    }
    for k, v in defaults.items():
        if k not in user:
            user[k] = v
    return user

# Arquivo onde os dados serão salvos permanentemente no seu PC
# Em produção (Render), aponte para um disco persistente via variável de ambiente DATA_FILE
DATA_FILE = os.environ.get("DATA_FILE", "bateria_data.json")

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
        except:
            pass

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

        data = {
            "users": {
                "admin": {
                    "passwordHash": hash_password("admin"),
                    "role": "admin",
                    "status": "active",
                    "firstName": "Administrador",
                    "lastName": "",
                    "email": "",
                    "phone": "",
                    "mustResetPassword": False,
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
    if changed:
        save_data(data)

    return data


def save_data(data):
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


@app.route('/api/login', methods=['POST'])
def login():
    creds = request.json or {}
    username = (creds.get('username') or '').strip()
    password = creds.get('password') or ''
    full_data = load_data()

    user = full_data['users'].get(username)
    if not user or not verify_password(password, user.get('passwordHash', '')):
        return jsonify({"success": False, "message": "Usuário ou senha incorretos."}), 401

    status = user.get('status', 'active')
    if status == 'pending':
        return jsonify({"success": False, "message": "Sua conta está aguardando aprovação do administrador."}), 403
    if status == 'disabled':
        return jsonify({"success": False, "message": "Sua conta foi desativada. Contate o administrador."}), 403

    return jsonify({
        "success": True,
        "token": username,
        "role": user['role'],
        "firstName": user.get('firstName', ''),
        "lastName": user.get('lastName', ''),
        "mustResetPassword": user.get('mustResetPassword', False)
    })


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
    user = request.headers.get('Authorization')
    full_data = load_data()
    if not user or user not in full_data['users']:
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
    user = request.headers.get('Authorization')
    full_data = load_data()

    if not user or user not in full_data['users']:
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
    user = request.headers.get('Authorization')
    payload = request.json
    full_data = load_data()

    if not user or user not in full_data['users']:
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


def _require_admin():
    user = request.headers.get('Authorization')
    full_data = load_data()
    if not user or user not in full_data['users'] or full_data['users'][user]['role'] != 'admin':
        return None, None, (jsonify({"error": "Não autorizado"}), 401)
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
            "createdAt": datetime.utcnow().isoformat() + "Z"
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


HTML_PAGE = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Biodron Smart Report Pro - Baterias</title>

    <script src="https://cdn.tailwindcss.com"></script>
    <script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
    <script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
    <script src="https://unpkg.com/htm@3.1.1/dist/htm.js"></script>
    <script src="https://unpkg.com/@phosphor-icons/web"></script>

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
                        userState: { headerData, answers, diagramMarks, reportImages, pdfMargin }
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
            }, [headerConfig, headerData, models, answers, diagramMarks, logo, reportImages, pdfMargin, isLoaded, auth]);

            // Salva status temp de fotos antes da câmera abrir
            useEffect(() => {
                if (pendingImages.length > 0) {
                    try { localStorage.setItem('smartReportPendingImages', JSON.stringify(pendingImages)); } catch(e) {}
                } else {
                    localStorage.removeItem('smartReportPendingImages');
                }
            }, [pendingImages]);

            // Busca lista de usuários quando admin abre a aba "Usuários"
            const fetchUsers = () => {
                fetch('/api/users', { headers: { 'Authorization': auth.token } })
                    .then(r => r.json()).then(data => { if(Array.isArray(data)) setUsersList(data); });
            };

            useEffect(() => {
                if (auth && auth.role === 'admin' && activeTab === 'users') {
                    fetchUsers();
                }
            }, [activeTab, auth]);

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
                        const newAuth = { token: data.token, role: data.role, firstName: data.firstName, lastName: data.lastName };
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
                localStorage.removeItem('smartReportAuth');
                setAuth(null);
                setIsLoaded(false);
                setActiveTab('report');
            };

            if (!auth) {
                return html`
                    <div className="min-h-screen bg-slate-100 flex items-center justify-center p-4">
                        <div className="bg-white p-8 rounded-2xl shadow-xl w-full max-w-md">
                            <div className="text-center mb-6">
                                <i className="ph-fill ph-device-mobile text-blue-600 text-5xl mb-2"></i>
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

            const confirmPendingImages = () => {
                setReportImages(prev => [...prev, ...pendingImages]);
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

                        {/* ASSINATURA DO TÉCNICO */}
                        <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                            <h2 className="text-xl font-semibold mb-4 text-slate-800 flex items-center gap-2">
                                <i className="ph-fill ph-signature text-blue-600 text-2xl"></i> Assinatura do Técnico
                            </h2>
                            <p className="text-sm text-slate-500 mb-3">A assinatura abaixo aparecerá no campo "Técnico Responsável" do PDF.</p>
                            <${SignaturePad} value=${headerData.technicianSignature || ''} onChange=${(dataUrl) => setHeaderData({...headerData, technicianSignature: dataUrl})} />
                        </div>

                        {/* PREFERÊNCIAS INDIVIDUAIS DO USUÁRIO PARA O LAUDO */}
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
                        <div className="bg-indigo-50 border border-indigo-200 p-4 rounded-xl flex items-center gap-3 text-indigo-800">
                            <i className="ph-fill ph-info text-2xl"></i>
                            <div>
                                <h3 className="font-bold">Aviso Administrativo</h3>
                                <p className="text-sm">As alterações feitas nesta aba afetam <b>todos os usuários</b> do sistema.</p>
                            </div>
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
                        phone: f.phone.value
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
                                <button type="submit" className="bg-blue-600 text-white px-6 py-2 rounded font-medium hover:bg-blue-700">Criar Usuário</button>
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
                            <div className="mt-16 flex justify-between px-10 prevent-break">
                                <div className="text-center w-64 relative">
                                    ${headerData.technicianSignature && html`
                                        <img src=${headerData.technicianSignature} alt="Assinatura" style=${{ height: '60px', objectFit: 'contain', margin: '0 auto', display: 'block', marginBottom: '-10px' }} />
                                    `}
                                    <div className="border-t border-black pt-2 font-semibold">Técnico Responsável</div>
                                </div>
                                <div className="text-center w-64 border-t border-black pt-2 font-semibold mt-12">Ciente do Cliente</div>
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
                            <div className="flex flex-col">
                                <h1 className="text-2xl font-bold flex items-center gap-2"><i className="ph-fill ph-device-mobile text-blue-400"></i> Biodron Smart Report Pro</h1>
                                <span className="text-slate-400 text-sm mt-1 flex items-center gap-2">
                                    <i className="ph-fill ph-user-circle"></i> Olá, <b className="text-white">${auth.token}</b>
                                    <button onClick=${handleLogout} className="ml-2 text-red-400 hover:text-red-300 underline font-medium text-xs">Sair da Conta</button>
                                </span>
                            </div>
                            <div className="flex gap-2">
                                <button onClick=${clearCurrentReport} className="px-4 py-2 bg-slate-800 rounded-lg text-sm font-medium hover:bg-slate-700 transition">Limpar Laudo</button>
                                <button onClick=${() => window.print()} className="px-4 py-2 bg-blue-600 rounded-lg font-medium flex items-center gap-2 hover:bg-blue-500 transition shadow-md"><i className="ph-bold ph-printer"></i> Gerar PDF</button>
                            </div>
                        </header>

                        <div className="flex space-x-1 mb-6 bg-slate-200 p-1 rounded-xl w-full md:w-fit overflow-x-auto scrollbar-hide">
                            <button onClick=${() => setActiveTab('report')} className=${`whitespace-nowrap px-6 py-2.5 rounded-lg text-sm font-medium flex items-center gap-2 transition-all ${activeTab === 'report' ? 'bg-white text-blue-700 shadow' : 'text-slate-600 hover:bg-slate-300'}`}><i className="ph-bold ph-file-text"></i> Preencher Laudo</button>

                            ${auth.role === 'admin' && html`
                                <button onClick=${() => setActiveTab('settings')} className=${`whitespace-nowrap px-6 py-2.5 rounded-lg text-sm font-medium flex items-center gap-2 transition-all ${activeTab === 'settings' ? 'bg-white text-indigo-700 shadow' : 'text-slate-600 hover:bg-slate-300'}`}><i className="ph-bold ph-gear"></i> Templates (Global)</button>
                                <button onClick=${() => setActiveTab('users')} className=${`whitespace-nowrap px-6 py-2.5 rounded-lg text-sm font-medium flex items-center gap-2 transition-all ${activeTab === 'users' ? 'bg-white text-emerald-700 shadow' : 'text-slate-600 hover:bg-slate-300'}`}><i className="ph-bold ph-users"></i> Usuários</button>
                            `}
                        </div>

                        <main>
                            ${activeTab === 'report' ? renderReportForm() : ''}
                            ${activeTab === 'settings' && auth.role === 'admin' ? renderSettings() : ''}
                            ${activeTab === 'users' && auth.role === 'admin' ? renderUsers() : ''}
                        </main>
                    </div>

                    <div className="print:hidden fixed bottom-4 right-4 bg-slate-800 text-white text-xs px-4 py-2 rounded-full shadow-lg flex items-center gap-2 opacity-90 transition-all z-50">
                        ${isSaving ? html`<span className="flex items-center gap-1"><i className="ph ph-spinner animate-spin"></i> Sincronizando...</span>` : html`<span className="flex items-center gap-1"><i className="ph-fill ph-check-circle text-green-400"></i> Salvo na Nuvem</span>`}
                    </div>

                    {/* MODAIS (FOTOS) */}
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
