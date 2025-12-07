

function updateActionButtons() {
    const newNoteBtn = document.getElementById('newNote');
    const saveAllBtn = document.getElementById('saveAll');
    const manageFilesBtn = document.getElementById('manageFiles');

    if (isPrivateSite && !isLoggedIn) {
        newNoteBtn.style.display = 'none';
        saveAllBtn.style.display = 'none';
        manageFilesBtn.style.display = 'none';
        return;
    }

    if (isPrivateSite && !isAdmin) {
        newNoteBtn.style.display = 'none';
        saveAllBtn.style.display = 'none';
        manageFilesBtn.style.display = 'none';
        return;
    }

    newNoteBtn.style.display = 'block';
    saveAllBtn.style.display = 'block';
    manageFilesBtn.style.display = 'block';
}