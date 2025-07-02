// static/script.js

const API_BASE_URL = 'http://127.0.0.1:5000/api'; // Flask backend URL

const masterPasswordInput = document.getElementById('masterPasswordInput');
const setMasterPasswordBtn = document.getElementById('setMasterPasswordBtn');
const verifyMasterPasswordBtn = document.getElementById('verifyMasterPasswordBtn');
const authMessage = document.getElementById('authMessage');
const authSection = document.getElementById('auth-section');
const managerSection = document.getElementById('manager-section');

const serviceNameInput = document.getElementById('serviceNameInput');
const passwordInput = document.getElementById('passwordInput');
const addUpdatePasswordBtn = document.getElementById('addUpdatePasswordBtn');
const managerMessage = document.getElementById('managerMessage');
const passwordList = document.getElementById('passwordList');
const copyPasswordBtn = document.getElementById('copyPasswordBtn');
const deletePasswordBtn = document.getElementById('deletePasswordBtn');
const decryptedOutput = document.getElementById('decryptedOutput');

let selectedPasswordId = null;

// --- Helper Functions ---
function showMessage(element, message, type) {
    element.textContent = message;
    element.className = `message ${type}`;
    setTimeout(() => {
        element.textContent = '';
        element.className = 'message';
    }, 5000); // Clear message after 5 seconds
}

function toggleManagerSection(show) {
    if (show) {
        managerSection.classList.remove('hidden');
        authSection.classList.add('hidden');
    } else {
        managerSection.classList.add('hidden');
        authSection.classList.remove('hidden');
    }
}

function clearSelection() {
    const currentSelected = document.querySelector('.password-item.selected');
    if (currentSelected) {
        currentSelected.classList.remove('selected');
    }
    selectedPasswordId = null;
    copyPasswordBtn.disabled = true;
    deletePasswordBtn.disabled = true;
    decryptedOutput.textContent = ''; // Clear decrypted output on new selection
}

// --- API Calls ---
async function checkMasterPasswordStatus() {
    try {
        const response = await fetch(`${API_BASE_URL}/master-password-status`);
        const data = await response.json();
        if (data.status === 'set') {
            setMasterPasswordBtn.disabled = true;
            masterPasswordInput.focus();
        } else {
            verifyMasterPasswordBtn.disabled = true;
            setMasterPasswordBtn.disabled = false;
        }
    } catch (error) {
        console.error('Error checking master password status:', error);
        showMessage(authMessage, 'Could not connect to backend.', 'error');
        setMasterPasswordBtn.disabled = true; // Disable all if backend isn't reachable
        verifyMasterPasswordBtn.disabled = true;
    }
}

async function setMasterPassword() {
    const master_password = masterPasswordInput.value;
    if (!master_password) {
        showMessage(authMessage, 'Master password cannot be empty.', 'error');
        return;
    }
    try {
        const response = await fetch(`${API_BASE_URL}/set-master-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ master_password })
        });
        const data = await response.json();
        if (data.success) {
            showMessage(authMessage, data.message, 'success');
            setMasterPasswordBtn.disabled = true;
            verifyMasterPasswordBtn.disabled = false;
            masterPasswordInput.value = ''; // Clear input
        } else {
            showMessage(authMessage, data.message, 'error');
        }
    } catch (error) {
        console.error('Error setting master password:', error);
        showMessage(authMessage, 'Failed to set master password. Network error?', 'error');
    }
}

async function verifyMasterPassword() {
    const master_password = masterPasswordInput.value;
    if (!master_password) {
        showMessage(authMessage, 'Please enter your master password.', 'error');
        return;
    }
    try {
        const response = await fetch(`${API_BASE_URL}/verify-master-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ master_password })
        });
        const data = await response.json();
        if (response.ok) { // Check for 2xx status codes
            showMessage(authMessage, data.message, 'success');
            masterPasswordInput.value = ''; // Clear input
            masterPasswordInput.disabled = true;
            setMasterPasswordBtn.disabled = true;
            verifyMasterPasswordBtn.disabled = true;
            toggleManagerSection(true);
            loadPasswords();
        } else {
            showMessage(authMessage, data.message, 'error');
            toggleManagerSection(false); // Hide manager if verification fails
        }
    } catch (error) {
        console.error('Error verifying master password:', error);
        showMessage(authMessage, 'Authentication failed. Network error?', 'error');
        toggleManagerSection(false);
    }
}

async function loadPasswords() {
    try {
        const response = await fetch(`${API_BASE_URL}/passwords`);
        const data = await response.json();

        passwordList.innerHTML = ''; // Clear existing list
        clearSelection(); // Clear any previous selection

        if (response.ok && data.success) {
            if (data.passwords.length === 0) {
                passwordList.innerHTML = '<li>No passwords stored yet.</li>';
            } else {
                data.passwords.forEach(pw => {
                    const listItem = document.createElement('li');
                    listItem.className = 'password-item';
                    listItem.dataset.id = pw.id;
                    listItem.innerHTML = `<span class="password-id">ID: ${pw.id}</span> <span class="service-name">${pw.service}</span>`;
                    listItem.addEventListener('click', () => {
                        clearSelection(); // Clear previous selection
                        listItem.classList.add('selected');
                        selectedPasswordId = pw.id;
                        copyPasswordBtn.disabled = false;
                        deletePasswordBtn.disabled = false;
                    });
                    passwordList.appendChild(listItem);
                });
            }
        } else {
            showMessage(managerMessage, data.message || 'Failed to load passwords.', 'error');
            toggleManagerSection(false); // Force re-authentication
        }
    } catch (error) {
        console.error('Error loading passwords:', error);
        showMessage(managerMessage, 'Failed to load passwords. Network error?', 'error');
        toggleManagerSection(false);
    }
}

async function addUpdatePassword() {
    const service = serviceNameInput.value.trim();
    const password = passwordInput.value;

    if (!service || !password) {
        showMessage(managerMessage, 'Service name and password cannot be empty.', 'error');
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/passwords`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ service, password })
        });
        const data = await response.json();
        if (response.ok) {
            showMessage(managerMessage, data.message, 'success');
            serviceNameInput.value = '';
            passwordInput.value = '';
            loadPasswords();
        } else {
            showMessage(managerMessage, data.message, 'error');
        }
    } catch (error) {
        console.error('Error adding/updating password:', error);
        showMessage(managerMessage, 'Failed to add/update password. Network error?', 'error');
    }
}

async function copyDecryptedPassword() {
    if (!selectedPasswordId) {
        showMessage(decryptedOutput, 'Please select a password to copy.', 'info');
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/passwords/decrypt/${selectedPasswordId}`);
        const data = await response.json();

        if (response.ok && data.success) {
            const decrypted_password = data.decrypted_password;
            navigator.clipboard.writeText(decrypted_password).then(() => {
                showMessage(decryptedOutput, 'Decrypted password copied to clipboard!', 'success');
            }).catch(err => {
                console.error('Failed to copy to clipboard:', err);
                showMessage(decryptedOutput, 'Failed to copy to clipboard. Please copy manually.', 'error');
                decryptedOutput.textContent = `Decrypted: ${decrypted_password}`;
            });
        } else {
            showMessage(decryptedOutput, data.message || 'Failed to decrypt password.', 'error');
        }
    } catch (error) {
        console.error('Error decrypting password for copy:', error);
        showMessage(decryptedOutput, 'Failed to get decrypted password. Network error?', 'error');
    }
}

async function deletePassword() {
    if (!selectedPasswordId) {
        showMessage(managerMessage, 'Please select a password to delete.', 'info');
        return;
    }

    if (!confirm('Are you sure you want to delete this password entry?')) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/passwords/${selectedPasswordId}`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
        });
        const data = await response.json();

        if (response.ok) {
            showMessage(managerMessage, data.message, 'success');
            loadPasswords(); // Reload list after deletion
        } else {
            showMessage(managerMessage, data.message, 'error');
        }
    } catch (error) {
        console.error('Error deleting password:', error);
        showMessage(managerMessage, 'Failed to delete password. Network error?', 'error');
    }
}

// --- Event Listeners ---
setMasterPasswordBtn.addEventListener('click', setMasterPassword);
verifyMasterPasswordBtn.addEventListener('click', verifyMasterPassword);
addUpdatePasswordBtn.addEventListener('click', addUpdatePassword);
copyPasswordBtn.addEventListener('click', copyDecryptedPassword);
deletePasswordBtn.addEventListener('click', deletePassword);

// Initial check on page load
document.addEventListener('DOMContentLoaded', checkMasterPasswordStatus);