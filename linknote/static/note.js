// State management
let notes = {};
let displayNotes = [];
let currentNote = null;
let loginCheckInterval = null;
let currentCaptcha = '';
let currentFile = 'data.js';
let currentNoteIndex = null;
let availableFiles = [];
let onGoingRequests = 0;


// DOM Elements
const searchInput = document.getElementById('search');
const notesList = document.getElementById('notesList');
const editDialog = document.getElementById('editDialog');
const sortBySelect = document.getElementById('sortBy');
const duplicateButton = document.getElementById('duplicate');
const isTemplateUrlCheckbox = document.getElementById('isTemplateUrl');
const templateParamsDiv = document.getElementById('templateParams');
const manageFilesBtn = document.getElementById('manageFiles');
const fileManagementDialog = document.getElementById('fileManagementDialog');
const moveNoteDialog = document.getElementById('moveNoteDialog');
const createFileDialog = document.getElementById('createFileDialog');
const targetFileSelect = document.getElementById('targetFile');
const editStackEditBtn = document.getElementById('editStackEdit');
const moveNoteBtn = document.getElementById('moveNote');
const uploadFileBtn = document.getElementById('uploadFile');
const fileInput = document.getElementById('fileInput');

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
manageFilesBtn.addEventListener('click', openFileManagement);
editStackEditBtn.addEventListener('click', openStackEdit);
moveNoteBtn.addEventListener('click', openMoveNoteDialog);
uploadFileBtn.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', uploadFiles);

searchInput.addEventListener('input', debounce(filterNotes, 300));
sortBySelect.addEventListener('change', () => filterNotes());

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
        filterNotes();
    } else {
        for (let f of availableFiles) {
            loadNotesFromFile(f.name);
        }
    }
}

function renderNotes(filtered = null) {
    if (filtered)
        displayNotes = filtered
    else {
        displayNotes = []
        for (let key in notes) {
            if (notes.hasOwnProperty(key)) {
                displayNotes = displayNotes.concat(notes[key]);
            }
        }
    }

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
    let filtered = []
    for (let key in notes) {
        const currentFiltered = notes[key].filter(note => {
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
        filtered = filtered.concat(currentFiltered)
    }
    renderNotes(filtered);
}

function openEditDialog(note = null) {
    currentNote = note
    currentNoteIndex = note ? notes[note.file].indexOf(note) : null;
    document.getElementById('editTitle').value = note ? note.title : '';
    document.getElementById('editLink').value = note ? note.link : '';
    document.getElementById('editTags').value = note ? note.tags.join(', ') : '';
    document.getElementById('editDescription').value = note ? note.description : '';
    document.getElementById('editAuthor').value = note ? note.author : localStorage.getItem(AUTHOR_KEY) || '';
    document.getElementById('targetFile').value = note && note.file ? note.file : 'data.js';
    // make it readonly
    document.getElementById('targetFile').disabled = !!note;
    isTemplateUrlCheckbox.checked = note ? note.isTemplateUrl : false;
    updateTemplateParams();

    duplicateButton.style.display = note ? 'block' : 'none';
    editStackEditBtn.style.display = note ? 'block' : 'none';
    moveNoteBtn.style.display = note ? 'block' : 'none';
    editDialog.classList.add('active');
}

function closeEditDialog() {
    editDialog.classList.remove('active');
    currentNote = null;
    templateParamsDiv.innerHTML = '';
}

function editNote(index) {
    if (requireLogin('edit')) {
        openEditDialog(displayNotes[index]);
    }
}

function duplicateNote() {
    if (!requireLogin('duplicate'))
        return
    if (!currentNote) return;
    const newNote = {...currentNote};
    newNote.createTime = Date.now();
    newNote.modifyTime = Date.now();
    newNote.title = `${newNote.title} copy`;
    notes[currentFile].push(newNote);
    closeEditDialog();
    filterNotes();
}

function duplicateNoteAt(index) {
    if (!requireLogin('duplicate'))
        return
    const note = displayNotes[index];
    currentFile = note.file;
    const newNote = {...note};
    newNote.createTime = Date.now();
    newNote.modifyTime = Date.now();
    newNote.title = `${newNote.title} copy`;
    notes[currentFile].push(newNote);
    filterNotes();
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
    if (!requireLogin('save'))
        return;

    const title = document.getElementById('editTitle').value.trim();
    const link = document.getElementById('editLink').value.trim();
    const tags = document.getElementById('editTags').value
        .split(',')
        .map(tag => tag.trim())
        .filter(Boolean);
    const description = document.getElementById('editDescription').value.trim();
    const author = document.getElementById('editAuthor').value.trim();
    const isTemplateUrl = isTemplateUrlCheckbox.checked;
    const targetFile = targetFileSelect.value;
    if (!title) {
        alert('Title is required!');
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
        const index = notes[currentFile].indexOf(currentNote);
        notes[currentFile][index] = note;
    } else {
        notes[targetFile].push(note);
    }

    closeEditDialog();
    filterNotes();
    await saveNotes(currentFile);
}

async function saveNotes(targetFile) {
    if (!targetFile) {
        // save all
        for (let file in notes) {
            await saveNotes(file);
        }
    }

    if (window.location.protocol === 'file:') {
        console.warn('Cannot save in static mode');
        return;
    }

    try {
        let notesToSave = []
        for (let n of notes[targetFile]) {
            let newNote = {}
            for (let k in n) {
                if (k === 'file' || k === 'index') continue; // Skip file and index
                newNote[k] = n[k];
            }
            notesToSave.push(newNote);
        }
        const response = await fetch('/api/notes', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ data: notesToSave, filepath: targetFile })
        });

        const result = await response.json();
        if (result.success) {
            currentFile = targetFile;
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


// Initialize
window.addEventListener('load', async () => {
    // Check if we're in public mode
    if (window.isPublicMode) {
        // Hide login elements and admin features for public mode
        document.getElementById('loginBtn').style.display = 'none';
        document.getElementById('userInfo').style.display = 'none';
        document.getElementById('newNote').style.display = 'none';
        // document.getElementById('saveAll').style.display = 'none';
        document.getElementById('manageFiles').style.display = 'none';
        currentFile = 'public.js';
        await loadNotes();
        //return;
    }
    await checkLoginType();
    await checkLoginState();
    if (isPrivateSite && !isAdmin) {
        availableFiles = [{
            'name': 'public.js',
            'is_public': true,
            'size': 0
        }];
    }
    else
        await loadAvailableFiles();

    await loadNotes();
    updateActionButtons();
});

deleteNote = (index) => {
    if (requireLogin('delete')) {
        if (confirm('Are you sure you want to delete this note?')) {
            const note = displayNotes[index];
            const file = note.file;
            const noteIndex = notes[file].indexOf(note);
            notes[file].splice(noteIndex, 1);
            filterNotes();
        }
    }
};

// File Management Functions
async function loadAvailableFiles() {
    try {
        const response = await fetch('/api/data-files');
        const result = await response.json();
        if (result.success) {
            availableFiles = result.files;
            updateFileSelects();
        }
    } catch (error) {
        console.error('Failed to load available files:', error);
    }
}

function updateFileSelects() {
    const selects = [targetFileSelect, document.getElementById('moveTargetFile')];
    selects.forEach(select => {
        if (select) {
            select.innerHTML = availableFiles.map(file => 
                `<option value="${file.name}">${file.name}${file.is_public ? ' (Public)' : ''}</option>`
            ).join('');
        }
    });
}

async function openFileManagement() {
    await loadUploadedFiles();
    await loadAvailableFiles();
    fileManagementDialog.classList.add('active');
}

function closeFileManagement() {
    fileManagementDialog.classList.remove('active');
}

async function loadUploadedFiles() {
    try {
        const response = await fetch('/api/files');
        const result = await response.json();
        if (result.success) {
            displayUploadedFiles(result.files);
        }
    } catch (error) {
        console.error('Failed to load uploaded files:', error);
    }
}

function displayUploadedFiles(files) {
    const container = document.getElementById('uploadedFilesList');
    container.innerHTML = files.map(file => `
        <div class="file-item">
            <div class="file-info">
                <strong>${escapeHtml(file.original_filename)}</strong>
                <div class="file-meta">
                    Size: ${formatFileSize(file.size)} | 
                    Type: ${file.mimetype} | 
                    Uploaded: ${new Date(file.upload_time * 1000).toLocaleString()}
                </div>
                <div class="file-url">
                    <input type="text" value="${window.location.origin}${file.url}" readonly>
                    <button onclick="copyToClipboard('${window.location.origin}${file.url}')">Copy URL</button>
                </div>
            </div>
            <div class="file-actions">
                <button onclick="window.open('${file.url}', '_blank')">View</button>
                <button onclick="deleteUploadedFile('${file.id}')">Delete</button>
            </div>
        </div>
    `).join('');
}

function displayDataFiles(files) {
    const container = document.getElementById('dataFilesList');
    container.innerHTML = files.map(file => `
        <div class="file-item">
            <div class="file-info">
                <strong>${escapeHtml(file.name)}</strong>
                ${file.is_public ? '<span class="public-badge">Public</span>' : ''}
                <div class="file-meta">Size: ${formatFileSize(file.size)}</div>
            </div>
            <div class="file-actions">
                <button onclick="loadNotesFromFile('${file.name}')">Load</button>
            </div>
        </div>
    `).join('');
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

async function uploadFiles() {
    const files = fileInput.files;
    if (files.length === 0) return;

    for (const file of files) {
        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch('/api/upload', {
                method: 'POST',
                body: formData
            });
            const result = await response.json();
            if (result.success) {
                alert(`File "${file.name}" uploaded successfully!`);
            } else {
                throw new Error(result.error);
            }
        } catch (error) {
            alert(`Failed to upload "${file.name}": ${error.message}`);
        }
    }

    fileInput.value = '';
    await loadUploadedFiles();
}

async function deleteUploadedFile(fileId) {
    if (!confirm('Are you sure you want to delete this file?')) return;

    try {
        const response = await fetch(`/api/files/${fileId}`, {
            method: 'DELETE'
        });
        const result = await response.json();
        if (result.success) {
            alert('File deleted successfully!');
            await loadUploadedFiles();
        } else {
            throw new Error(result.error);
        }
    } catch (error) {
        alert(`Failed to delete file: ${error.message}`);
    }
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        alert('URL copied to clipboard!');
    }).catch(err => {
        console.error('Failed to copy URL:', err);
    });
}

async function createNewFile() {
    const filename = document.getElementById('createFileName').value.trim();
    if (!filename) {
        alert('Please enter a filename');
        return;
    }

    try {
        const response = await fetch('/api/data-files', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename })
        });
        const result = await response.json();
        if (result.success) {
            alert(`File "${result.filename}" created successfully!`);
            createFileDialog.classList.remove('active');
            document.getElementById('createFileName').value = '';
            await loadAvailableFiles();
        } else {
            throw new Error(result.error);
        }
    } catch (error) {
        alert(`Failed to create file: ${error.message}`);
    }
}

async function loadNotesFromFile(filename) {
    currentFile = filename;
    try {
        onGoingRequests += 1;
        const response = await fetch(`/api/notes?file=${encodeURIComponent(filename)}`);
        const result = await response.json();
        if (result.success) {
            let data = result.data
            let index = 0;
            for (let n of data) {
                n.file = filename; // Update file reference for existing notes
                n.index = index
                ++index
            }
            notes[filename] = data
            console.log(`Loaded notes from ${filename}`);
        } else {
            throw new Error(result.error);
        }
        onGoingRequests -= 1;
        if (onGoingRequests === 0)
            filterNotes();
    } catch (error) {
        onGoingRequests -= 1;
        alert(`Failed to load notes from ${filename}: ${error.message}`);
    }
}

// StackEdit Integration
function openStackEdit() {
    const el = document.getElementById('editDescription');
    const stackedit = new Stackedit();
    // Open the iframe
    stackedit.openFile({
        name: 'Filename', // with an optional filename
        content: {
            text: el.value // and the Markdown content.
        }
    });

    // Listen to StackEdit events and apply the changes to the textarea.
    stackedit.on('fileChange', (file) => {
        el.value = file.content.text;
    });
}

// Move Note Functions
function openMoveNoteDialog() {
    if (!currentNote || currentNoteIndex === null) return;

    // Update target file options
    updateFileSelects();
    moveNoteDialog.classList.add('active');
}

function closeMoveNoteDialog() {
    moveNoteDialog.classList.remove('active');
}

async function moveNoteToFile() {
    const targetFile = document.getElementById('moveTargetFile').value;
    if (!targetFile || targetFile === currentFile) {
        alert('Please select a different target file');
        return;
    }

    try {
        const response = await fetch('/api/notes/move', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                source_file: currentFile,
                target_file: targetFile,
                note_index: currentNoteIndex
            })
        });
        const result = await response.json();
        if (result.success) {
            alert(`Note moved to ${targetFile} successfully!`);
            closeMoveNoteDialog();
            closeEditDialog();
            await loadNotes(); // Reload current file
        } else {
            throw new Error(result.error);
        }
    } catch (error) {
        alert(`Failed to move note: ${error.message}`);
    }
}

// Update editNote function to pass index
function editNote(index) {
    const note = displayNotes[index];
    currentNoteIndex = notes[currentFile].indexOf(note);
    openEditDialog(note);
}

// File Management Event Listeners
document.getElementById('closeFileManagement').addEventListener('click', closeFileManagement);
document.getElementById('uploadBtn').addEventListener('click', () => document.getElementById('uploadInput').click());
document.getElementById('uploadInput').addEventListener('change', async (e) => {
    const files = Array.from(e.target.files);
    for (const file of files) {
        const formData = new FormData();
        formData.append('file', file);
        try {
            const response = await fetch('/api/upload', {
                method: 'POST',
                body: formData
            });
            const result = await response.json();
            if (!result.success) {
                throw new Error(result.error);
            }
        } catch (error) {
            alert(`Failed to upload ${file.name}: ${error.message}`);
        }
    }
    e.target.value = '';
    await loadUploadedFiles();
});

document.getElementById('createFileBtn').addEventListener('click', createNewFile);
document.getElementById('confirmCreateFile').addEventListener('click', createNewFile);
document.getElementById('cancelCreateFile').addEventListener('click', () => {
    createFileDialog.classList.remove('active');
});
document.getElementById('createNewFile').addEventListener('click', () => {
    createFileDialog.classList.add('active');
});

document.getElementById('confirmMoveNote').addEventListener('click', moveNoteToFile);
document.getElementById('cancelMoveNote').addEventListener('click', closeMoveNoteDialog);

// Tab switching for file management
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const tab = btn.dataset.tab;

        // Update active tab button
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        // Update active tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(`${tab}FilesTab`).classList.add('active');

        // Load appropriate content
        if (tab === 'uploaded') {
            loadUploadedFiles();
        } else if (tab === 'data') {
            loadAvailableFiles().then(() => {
                displayDataFiles(availableFiles);
            });
        }
    });
});
