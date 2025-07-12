// State management
let notes = [];
let displayNotes = [];
let currentNote = null;
let loginCheckInterval = null;
let currentCaptcha = '';
const AUTHOR_KEY = 'linknote_author';
const LOGIN_CHECK_INTERVAL = 2000; // 2 seconds
const LOGIN_TIMEOUT = 300000; // 5 minutes

// Function to get CAPTCHA from backend
async function drawCaptcha() {
    try {
        const response = await fetch('/api/captcha');
        const data = await response.json();
        if (data.success) {
            const img = document.getElementById('captchaImage');
            img.src = data.image;
        } else {
            console.error('Failed to get CAPTCHA');
        }
    } catch (error) {
        console.error('Failed to get CAPTCHA:', error);
    }
}

// Login state
let isLoginEnabled = false;
let isLoggedIn = false;
let userInfo = null;
let loginType = 'oauth';
let emailLoginEnabled = false;
let isPrivateSite = false;
let isAdmin = false;

// DOM Elements
const searchInput = document.getElementById('search');
const notesList = document.getElementById('notesList');
const editDialog = document.getElementById('editDialog');
const loginDialog = document.getElementById('loginDialog');
const loginBtn = document.getElementById('loginBtn');
const logoutBtn = document.getElementById('logoutBtn');
const userInfoDiv = document.getElementById('userInfo');
const usernameSpan = document.getElementById('username');
const loginStatusDiv = document.getElementById('loginStatus');
const saveLocationSelect = document.getElementById('saveLocation');
const customPathInput = document.getElementById('customPath');
const fileTypeSelect = document.getElementById('fileType');
const sortBySelect = document.getElementById('sortBy');
const duplicateButton = document.getElementById('duplicate');
const isTemplateUrlCheckbox = document.getElementById('isTemplateUrl');
const templateParamsDiv = document.getElementById('templateParams');

// Initialize marked for markdown rendering
const marked = (text) => {
    return text
        .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank">$1</a>')
        .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
        .replace(/\*([^*]+)\*/g, '<em>$1</em>')
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        .replace(/\n/g, '<br>');
};

// Event Listeners
document.getElementById('newNote').addEventListener('click', () => {
    currentNote = null;
    duplicateButton.style.display = 'none';
    openEditDialog();
});

document.getElementById('saveAll').addEventListener('click', saveNotes);
document.getElementById('saveNote').addEventListener('click', saveNote);
document.getElementById('cancelEdit').addEventListener('click', closeEditDialog);
duplicateButton.addEventListener('click', duplicateNote);

saveLocationSelect.addEventListener('change', () => {
    const isCustom = saveLocationSelect.value === 'custom';
    customPathInput.style.display = isCustom ? 'block' : 'none';
    fileTypeSelect.style.display = isCustom ? 'block' : 'none';
});

searchInput.addEventListener('input', debounce(filterNotes, 300));
sortBySelect.addEventListener('change', () => renderNotes());

isTemplateUrlCheckbox.addEventListener('change', () => {
    updateTemplateParams();
    if (!isTemplateUrlCheckbox.checked) {
        templateParamsDiv.innerHTML = '';
    }
});

document.getElementById('editLink').addEventListener('input', updateTemplateParams);

// Functions
async function loadNotes() {
    // Load saved author from localStorage
    const savedAuthor = localStorage.getItem(AUTHOR_KEY);
    if (savedAuthor) {
        document.getElementById('editAuthor').value = savedAuthor;
    }

    if (window.location.protocol === 'file:') {
        notes = window.data || [];
        renderNotes();
    } else {
        try {
            const response = await fetch('/api/notes');
            const result = await response.json();
            if (result.success) {
                notes = result.data;
                renderNotes();
            }
        } catch (error) {
            console.error('Failed to load notes:', error);
        }
    }
}

function renderNotes(filtered = null) {
    displayNotes = filtered || [...notes];
    
    // Sort notes
    const sortBy = sortBySelect.value;
    displayNotes.sort((a, b) => {
        switch (sortBy) {
            case 'createTime':
                return b.createTime - a.createTime;
            case 'link':
                return a.link.localeCompare(b.link);
            case 'title':
            default:
                return a.title.localeCompare(b.title);
        }
    });

    notesList.innerHTML = displayNotes.map((note, index) => {
        const createDate = new Date(note.createTime);
        const modifyDate = new Date(note.modifyTime);
        
        let linkHtml = '';
        if (note.isTemplateUrl) {
            linkHtml = `
                <div class="template-url">
                    <a href="${escapeHtml(note.link)}" target="_blank" class="link">${escapeHtml(note.link)}</a>
                    <form class="template-params" onsubmit="return false;">
                        ${extractUrlParams(note.link).map(param => `
                            <div class="param-input">
                                <label for="param-${param}-${index}">${param}:</label>
                                <input type="text" id="param-${param}-${index}" 
                                       onkeyup="updateTemplateUrl(${index})">
                            </div>
                        `).join('')}
                    </form>
                </div>`;
        } else {
            linkHtml = `<a href="${escapeHtml(note.link)}" target="_blank" class="link">${escapeHtml(note.link)}</a>`;
        }

        return `
            <div class="note-card">
                <h3>${escapeHtml(note.title)}</h3>
                <div class="metadata">
                    ${note.author ? `<span class="author">By ${escapeHtml(note.author)}</span>` : ''}
                    <span class="timestamp">Created: ${createDate.toLocaleString()}</span>
                    <span class="timestamp">Modified: ${modifyDate.toLocaleString()}</span>
                </div>
                ${linkHtml}
                <div class="tags">
                    ${note.tags.map(tag => `<span class="tag">${escapeHtml(tag)}</span>`).join('')}
                </div>
                <div class="description">${marked(escapeHtml(note.description))}</div>
                <div class="actions">
                    <button class="edit" onclick="editNote(${index})">Edit</button>
                    <button class="duplicate" onclick="duplicateNoteAt(${index})">Duplicate</button>
                    <button class="delete" onclick="deleteNote(${index})">Delete</button>
                </div>
            </div>
        `;
    }).join('');

    // Setup template URL handlers
    displayNotes.forEach((note, index) => {
        if (note.isTemplateUrl) {
            updateTemplateUrl(index);
        }
    });
}

function filterNotes() {
    const query = searchInput.value;
    if (!query) {
        renderNotes();
        return;
    }

    // Parse query for quoted phrases
    const terms = [];
    let currentTerm = '';
    let inQuotes = false;

    for (let i = 0; i < query.length; i++) {
        if (query[i] === '"') {
            inQuotes = !inQuotes;
            if (!inQuotes && currentTerm) {
                terms.push(currentTerm.trim().toLowerCase());
                currentTerm = '';
            }
        } else if (query[i] === ' ' && !inQuotes) {
            if (currentTerm) {
                terms.push(currentTerm.trim().toLowerCase());
                currentTerm = '';
            }
        } else {
            currentTerm += query[i];
        }
    }
    if (currentTerm) {
        terms.push(currentTerm.trim().toLowerCase());
    }

    const filtered = notes.filter(note => {
        const title = note.title.toLowerCase();
        const desc = note.description.toLowerCase();
        const tags = note.tags.map(t => t.toLowerCase());
        const author = (note.author || '').toLowerCase();

        return terms.every(term => {
            return title.includes(term) ||
                   desc.includes(term) ||
                   tags.some(tag => tag.includes(term)) ||
                   author.includes(term);
        });
    });

    renderNotes(filtered);
}

function openEditDialog(note = null) {
    currentNote = note;
    document.getElementById('editTitle').value = note ? note.title : '';
    document.getElementById('editLink').value = note ? note.link : '';
    document.getElementById('editTags').value = note ? note.tags.join(', ') : '';
    document.getElementById('editDescription').value = note ? note.description : '';
    document.getElementById('editAuthor').value = note ? note.author : localStorage.getItem(AUTHOR_KEY) || '';
    
    isTemplateUrlCheckbox.checked = note ? note.isTemplateUrl : false;
    updateTemplateParams();
    
    duplicateButton.style.display = note ? 'block' : 'none';
    editDialog.classList.add('active');
}

function closeEditDialog() {
    editDialog.classList.remove('active');
    currentNote = null;
    templateParamsDiv.innerHTML = '';
}

function editNote(index) {
    openEditDialog(displayNotes[index]);
}

function duplicateNote() {
    if (!currentNote) return;
    const newNote = {...currentNote};
    newNote.createTime = Date.now();
    newNote.modifyTime = Date.now();
    newNote.title = `${newNote.title} copy`;
    notes.push(newNote);
    closeEditDialog();
    renderNotes();
}

function duplicateNoteAt(index) {
    const note = displayNotes[index];
    const newNote = {...note};
    newNote.createTime = Date.now();
    newNote.modifyTime = Date.now();
    newNote.title = `${newNote.title} copy`;
    notes.push(newNote);
    renderNotes();
}

function deleteNote(index) {
    if (confirm('Are you sure you want to delete this note?')) {
        notes.splice(index, 1);
        renderNotes();
    }
}

function updateTemplateParams() {
    if (!isTemplateUrlCheckbox.checked) {
        templateParamsDiv.innerHTML = '';
        return;
    }

    const link = document.getElementById('editLink').value;
    const params = extractUrlParams(link);
    
    if (params.length === 0) {
        templateParamsDiv.innerHTML = '<p>No parameters found. Use {paramName} in URL to define parameters.</p>';
        return;
    }

    templateParamsDiv.innerHTML = params.map(param => `
        <div class="param-input">
            <label for="dialog-param-${param}">${param}:</label>
            <input type="text" id="dialog-param-${param}">
        </div>
    `).join('') + '<div class="template-url-preview"></div>';

    // Add input handlers
    params.forEach(param => {
        document.getElementById(`dialog-param-${param}`).addEventListener('input', 
            () => updateTemplateUrlPreview(link));
    });
    updateTemplateUrlPreview(link);
}

function updateTemplateUrl(noteIndex) {
    const note = displayNotes[noteIndex];
    const form = document.querySelector(`#notesList .note-card:nth-child(${noteIndex + 1}) .template-params`);
    if (!form) return;

    const inputs = form.querySelectorAll('input');
    const params = {};
    inputs.forEach(input => {
        const paramName = input.id.split('-')[1];
        params[paramName] = input.value;
    });

    const finalUrl = replaceUrlParams(note.link, params);
    const linkElem = form.parentElement.querySelector('a');
    if (linkElem) {
        linkElem.href = finalUrl;
    }
}

function updateTemplateUrlPreview(templateUrl) {
    const preview = document.querySelector('.template-url-preview');
    if (!preview) return;

    const params = {};
    const paramInputs = templateParamsDiv.querySelectorAll('input');
    paramInputs.forEach(input => {
        const paramName = input.id.replace('dialog-param-', '');
        params[paramName] = input.value;
    });

    const finalUrl = replaceUrlParams(templateUrl, params);
    preview.textContent = finalUrl;
}

function extractUrlParams(url) {
    const params = new Set();
    const matches = url.match(/\{([^}]+)\}/g) || [];
    matches.forEach(match => params.add(match.slice(1, -1)));
    return Array.from(params);
}

function replaceUrlParams(url, params) {
    let result = url;
    for (const [key, value] of Object.entries(params)) {
        result = result.replace(new RegExp(`\\{${key}\\}`, 'g'), value || `{${key}}`);
    }
    return result;
}

async function saveNote() {
    const title = document.getElementById('editTitle').value.trim();
    const link = document.getElementById('editLink').value.trim();
    const tags = document.getElementById('editTags').value
        .split(',')
        .map(tag => tag.trim())
        .filter(Boolean);
    const description = document.getElementById('editDescription').value.trim();
    const author = document.getElementById('editAuthor').value.trim();
    const isTemplateUrl = isTemplateUrlCheckbox.checked;

    if (!title || !link) {
        alert('Title and link are required!');
        return;
    }

    // Save author to localStorage
    if (author) {
        localStorage.setItem(AUTHOR_KEY, author);
    }

    const note = {
        title,
        link,
        tags,
        description,
        author,
        isTemplateUrl,
        createTime: currentNote ? currentNote.createTime : Date.now(),
        modifyTime: Date.now()
    };
    
    if (currentNote) {
        const index = notes.indexOf(currentNote);
        notes[index] = note;
    } else {
        notes.push(note);
    }

    closeEditDialog();
    renderNotes();
    await saveNotes();
}

async function saveNotes() {
    const isCustom = saveLocationSelect.value === 'custom';
    const filepath = isCustom ? customPathInput.value : '';
    
    if (window.location.protocol === 'file:') {
        console.warn('Cannot save in static mode');
        return;
    }

    try {
        const response = await fetch('/api/notes', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ data: notes, filepath })
        });
        
        const result = await response.json();
        if (result.success) {
            alert('Notes saved successfully!');
        } else {
            throw new Error(result.error);
        }
    } catch (error) {
        console.error('Failed to save notes:', error);
        alert('Failed to save notes: ' + error.message);
    }
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function debounce(func, wait) {
    let timeout;
    return function(...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
    };
}

// Login Functions
async function checkLoginEnabled() {
    try {
        const response = await fetch('/api/notes');
        // isLoginEnabled = response.headers.get('X-Login-Enabled') === 'true';
        loginBtn.style.display = isLoginEnabled ? 'block' : 'none';
    } catch (error) {
        console.error('Failed to check login status:', error);
    }
}

async function requestLogin() {
    try {
        // Get login type first
        const typeResponse = await fetch('/api/login/type');
        const typeResult = await typeResponse.json();
        
        if (!typeResult.success) {
            throw new Error(typeResult.error);
        }

        loginType = typeResult.type;
        emailLoginEnabled = typeResult.email_enabled;

        // Show appropriate login method
        document.getElementById('oauthLogin').style.display = loginType === 'oauth' ? 'block' : 'none';
        document.getElementById('emailLogin').style.display = loginType === 'email' ? 'block' : 'none';

        if (loginType === 'oauth') {
            loginStatusDiv.textContent = 'Generating login QR code...';
            loginStatusDiv.className = '';
            
            const response = await fetch('/api/login/request', {
                method: 'POST'
            });
            const result = await response.json();
            
            if (!result.success) {
                throw new Error(result.error);
            }
            
            // Generate QR Code
            const qrCodeDiv = document.getElementById('qrCode');
            qrCodeDiv.innerHTML = '';
            await QRCode.toCanvas(qrCodeDiv, result.login_url, {
                width: 256,
                margin: 2
            });
            
            // Start checking login status
            startLoginCheck();
        }
    } catch (error) {
        loginStatusDiv.textContent = `Login failed: ${error.message}`;
        loginStatusDiv.className = 'error';
    }
}

async function requestEmailLogin() {
    try {
        const email = document.getElementById('loginEmail').value;
        if (!email) {
            throw new Error('Email is required');
        }

        loginStatusDiv.textContent = 'Sending login email...';
        loginStatusDiv.className = '';

        const response = await fetch('/api/login/email/request', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
        body: JSON.stringify({ 
            email,
            captcha: document.getElementById('captchaInput').value
        })
        });

        const result = await response.json();
        if (!result.success) {
            throw new Error(result.error);
        }

        loginStatusDiv.textContent = 'Login email sent! Please check your inbox.';
        loginStatusDiv.className = 'success';
        document.getElementById('loginEmail').value = '';
        startLoginCheck();
    } catch (error) {
        loginStatusDiv.textContent = `Login failed: ${error.message}`;
        loginStatusDiv.className = 'error';
    }
}

function startLoginCheck() {
    let startTime = Date.now();
    loginStatusDiv.textContent = 'Waiting for login...';
    loginStatusDiv.className = '';
    
    loginCheckInterval = setInterval(async () => {
        try {
            // Check timeout
            if (Date.now() - startTime > LOGIN_TIMEOUT) {
                clearInterval(loginCheckInterval);
                loginStatusDiv.textContent = 'Login timeout. Please try again.';
                loginStatusDiv.className = 'error';
                return;
            }
            
            let response;
            if (loginType === 'email') {
                response = await fetch('/api/login/email/status');
            } else {
                response = await fetch('/api/login/check');
            }
            const result = await response.json();
            
            if (result.success) {
                clearInterval(loginCheckInterval);
                userInfo = result.user_info || { email: result.email };
                isLoggedIn = true;
                closeLoginDialog();
                updateLoginUI();
                updateActionButtons();
                if (!isPrivateSite || isLoggedIn) {
                    await loadNotes();
                }
            } else if (loginType === 'email' && result.status === 'pending') {
                loginStatusDiv.textContent = `Waiting for login (sent to ${result.email})...`;
            }
        } catch (error) {
            console.error('Failed to check login status:', error);
        }
    }, LOGIN_CHECK_INTERVAL);
}

function updateLoginUI() {
    if (isLoggedIn && userInfo) {
        loginBtn.style.display = 'none';
        userInfoDiv.style.display = 'flex';
        usernameSpan.textContent = userInfo.name || userInfo.email || 'User';
    } else {
        loginBtn.style.display = isLoginEnabled ? 'block' : 'none';
        userInfoDiv.style.display = 'none';
        usernameSpan.textContent = '';
    }
}

function openLoginDialog() {
    loginDialog.classList.add('active');
}

function closeLoginDialog() {
    loginDialog.classList.remove('active');
    if (loginCheckInterval) {
        clearInterval(loginCheckInterval);
        loginCheckInterval = null;
    }
}

async function logout() {
    try {
        await fetch('/api/logout');
        isLoggedIn = false;
        userInfo = null;
        updateLoginUI();
        updateActionButtons();
        if (isPrivateSite) {
            notes = [];
            renderNotes();
        }
    } catch (error) {
        console.error('Failed to logout:', error);
    }
}

// Check if operation is allowed
function requireLogin(operation) {
    if (!isLoginEnabled || isLoggedIn) {
        return true;
    }
    alert('Please login to perform this operation');
    return false;
}

// Event Listeners for Login
// Event Listeners for Login
loginBtn.addEventListener('click', () => {
    openLoginDialog();
    requestLogin();
    drawCaptcha(); // Generate initial CAPTCHA
});

document.getElementById('sendLoginEmail').addEventListener('click', () => {
    requestEmailLogin();
});

document.getElementById('refreshCaptcha').addEventListener('click', () => {
    drawCaptcha();
    document.getElementById('captchaInput').value = '';
});

logoutBtn.addEventListener('click', logout);

document.getElementById('cancelLogin').addEventListener('click', closeLoginDialog);

// Login check and initialization
async function checkLoginType() {
    try {
        const response = await fetch('/api/login/type');
        const result = await response.json();
        if (result.success) {
            loginType = result.type;
            emailLoginEnabled = result.email_enabled;
            isPrivateSite = result.private;
            if (emailLoginEnabled)
            {
                isLoginEnabled = true;
                updateLoginUI();
            }   
        }
    } catch (error) {
        console.error('Failed to check login type:', error);
    }
}

async function checkLoginState() {
    try {
        const response = await fetch('/api/login/state');
        const state = await response.json();
        isLoggedIn = state.logged_in;
        isAdmin = state.is_admin;
        if (state.logged_in) {
            userInfo = state.user_info;
            updateLoginUI();
        }
    } catch (error) {
        console.error('Failed to check login state:', error);
    }
}

function updateActionButtons() {
    const newNoteBtn = document.getElementById('newNote');
    const saveAllBtn = document.getElementById('saveAll');
    
    if (isPrivateSite && !isLoggedIn) {
        newNoteBtn.style.display = 'none';
        saveAllBtn.style.display = 'none';
        return;
    }
    
    if (isPrivateSite && !isAdmin) {
        newNoteBtn.style.display = 'none';
        saveAllBtn.style.display = 'none';
        return;
    }
    
    newNoteBtn.style.display = 'block';
    saveAllBtn.style.display = 'block';
}

// Initialize
window.addEventListener('load', async () => {
    await checkLoginType();
    await checkLoginState();
    if (!isPrivateSite || isLoggedIn) {
        await loadNotes();
    }
    updateActionButtons();
});

// Update protected operations
const originalEditNote = editNote;
const originalDeleteNote = deleteNote;
const originalSaveNote = saveNote;
const originalDuplicateNote = duplicateNote;
const originalDuplicateNoteAt = duplicateNoteAt;

editNote = (index) => {
    if (requireLogin('edit')) {
        originalEditNote(index);
    }
};

deleteNote = (index) => {
    if (requireLogin('delete')) {
        originalDeleteNote(index);
    }
};

saveNote = async () => {
    if (requireLogin('save')) {
        await originalSaveNote();
    }
};

duplicateNote = () => {
    if (requireLogin('duplicate')) {
        originalDuplicateNote();
    }
};

duplicateNoteAt = (index) => {
    if (requireLogin('duplicate')) {
        originalDuplicateNoteAt(index);
    }
};
