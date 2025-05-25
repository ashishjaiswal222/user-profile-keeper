// Utility: Show a section and hide others
function showSection(sectionId) {
  document.querySelectorAll('.section').forEach(sec => sec.classList.remove('active'));
  const activeSec = document.getElementById(sectionId);
  if (activeSec) activeSec.classList.add('active');
}

// Utility: Parse query parameters
function getQueryParams() {
  const params = {};
  window.location.search.substr(1).split('&').forEach(item => {
    const [key, value] = item.split('=');
    if (key) params[key] = decodeURIComponent(value);
  });
  return params;
}

// -------------- Handle Profile Click --------------
function handleProfileClick() {
  const token = localStorage.getItem('token');
  if (!token) {
    alert('Please log in first.');
    showSection('login');
  } else {
    getUserProfile();
    showSection('profile');
  }
}

// -------------- User Registration --------------
document.getElementById('registerForm')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const data = Object.fromEntries(new FormData(e.target));
  try {
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    const result = await res.json();
    const msgEl = document.getElementById('registerMessage');
    if (!res.ok) {
      msgEl.textContent = result.error || 'Registration failed.';
      msgEl.classList.add('error');
    } else {
      msgEl.textContent = result.message;
      msgEl.classList.remove('error');
      localStorage.setItem('tempEmail', data.email);
      setTimeout(() => showSection('otp'), 1500);
    }
  } catch (err) {
    console.error(err);
    document.getElementById('registerMessage').textContent = 'An error occurred during registration.';
  }
});

// -------------- OTP Verification --------------
document.getElementById('otpForm')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const otp = document.getElementById('otpInput').value;
  const email = localStorage.getItem('tempEmail');
  try {
    const res = await fetch('/api/auth/verify-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, otp })
    });
    const result = await res.json();
    const msgEl = document.getElementById('otpMessage');
    if (!res.ok) {
      msgEl.textContent = result.error || 'OTP verification failed.';
      msgEl.classList.add('error');
    } else {
      msgEl.textContent = result.message;
      msgEl.classList.remove('error');
      setTimeout(() => showSection('login'), 1500);
    }
  } catch (err) {
    console.error(err);
    document.getElementById('otpMessage').textContent = 'An error occurred during OTP verification.';
  }
});

// -------------- User Login --------------
document.getElementById('loginForm')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const data = Object.fromEntries(new FormData(e.target));
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    const result = await res.json();
    const msgEl = document.getElementById('loginMessage');
    if (!res.ok) {
      msgEl.textContent = result.error || 'Login failed.';
      msgEl.classList.add('error');
    } else {
      msgEl.textContent = 'Login successful!';
      msgEl.classList.remove('error');
      localStorage.setItem('token', result.token);
      localStorage.setItem('user', JSON.stringify(result.user));
      setTimeout(() => {
        getUserProfile();
        showSection('profile');
      }, 1500);
    }
  } catch (err) {
    console.error(err);
    document.getElementById('loginMessage').textContent = 'An error occurred during login.';
  }
});

// -------------- Forgot Password --------------
document.getElementById('forgotForm')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const data = Object.fromEntries(new FormData(e.target));
  try {
    const res = await fetch('/api/auth/forgot-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    const result = await res.json();
    const msgEl = document.getElementById('forgotMessage');
    if (!res.ok) {
      msgEl.textContent = result.error || 'Request failed.';
      msgEl.classList.add('error');
    } else {
      msgEl.textContent = result.message;
      msgEl.classList.remove('error');
      setTimeout(() => showSection('login'), 2000);
    }
  } catch (err) {
    console.error(err);
    document.getElementById('forgotMessage').textContent = 'An error occurred.';
  }
});

// -------------- Reset Password --------------
// This logic will only run if the resetForm exists on the current page (i.e., reset-password.html)
const resetForm = document.getElementById('resetForm');
if (resetForm) {
  // Extract token and email from URL query parameters when the page loads
  const queryParams = getQueryParams();
  const token = queryParams.token;
  const email = queryParams.email;

  // Pre-fill email if available, though not strictly necessary for submission
  // const emailInput = document.getElementById('resetEmail'); // Assuming an input field for email exists
  // if (emailInput && email) {
  //   emailInput.value = email;
  //   emailInput.readOnly = true; // Optional: make it read-only
  // }

  resetForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const newPassword = document.getElementById('newPassword').value;
    const msgEl = document.getElementById('resetMessage');

    if (!token || !email) {
      msgEl.textContent = 'Missing token or email from URL. Please use the link from your email.';
      msgEl.classList.add('error');
      return;
    }

    if (!newPassword) {
      msgEl.textContent = 'Please enter a new password.';
      msgEl.classList.add('error');
      return;
    }
    msgEl.textContent = ''; // Clear previous messages
    msgEl.classList.remove('error');

    try {
      const res = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, token, newPassword })
      });
      const result = await res.json();
      if (!res.ok) {
        msgEl.textContent = result.error || 'Password reset failed.';
        msgEl.classList.add('error');
      } else {
        msgEl.textContent = result.message || 'Password has been reset successfully.';
        msgEl.classList.remove('error');
        setTimeout(() => {
          showSection('login');
          // Clear the form or redirect to login, potentially clearing URL params
          window.history.pushState({}, document.title, window.location.pathname.replace('reset-password.html', '') + '#login');
          resetForm.reset(); // Clear the password field
        }, 2000);
      }
    } catch (err) {
      console.error('Reset Password Error:', err);
      msgEl.textContent = 'An error occurred during password reset. Please try again.';
      msgEl.classList.add('error');
    }
  });
}

// -------------- Fetch and Display User Profile --------------
async function getUserProfile() {
  const token = localStorage.getItem('token');
  if (!token) {
    alert('Please log in first.');
    showSection('login');
    return;
  }
  try {
    const res = await fetch('/api/auth/profile', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + token }
    });
    const result = await res.json();
    if (!res.ok) {
      alert(result.error || 'Failed to fetch profile. Please log in again.');
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      showSection('login');
      return;
    }
    const user = result.user;
    document.getElementById('pName').textContent = user.name;
    document.getElementById('pEmail').textContent = user.email;
    document.getElementById('pContact').textContent = user.contact;
    document.getElementById('pDob').textContent = user.dob;
    document.getElementById('pCity').textContent = user.city;
  } catch (err) {
    console.error(err);
    alert('An error occurred while fetching profile.');
  }
}

// -------------- Logout (User) --------------
document.getElementById('logoutBtn')?.addEventListener('click', () => {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
  // Optionally, disable the profile link after logout
  document.getElementById('profileNav').classList.add('disabled');
  showSection('landing');
});

// -------------- Admin Registration: Request Approval --------------
document.getElementById('requestApprovalBtn')?.addEventListener('click', async () => {
  const name = document.getElementById('adminName').value.trim();
  const email = document.getElementById('adminEmail').value.trim();
  if (!name || !email) {
    alert('Please enter your name and email.');
    return;
  }
  try {
    const res = await fetch('/api/auth/admin/request-registration', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, email })
    });
    const result = await res.json();
    const statusEl = document.getElementById('adminRequestStatus');
    if (!res.ok) {
      statusEl.textContent = result.error || 'Request failed.';
      statusEl.classList.add('error');
    } else {
      statusEl.textContent = result.message;
      statusEl.classList.remove('error');
      // For demo purposes, automatically reveal the complete registration section
      // In production, this should wait for owner approval.
      document.getElementById('adminApprovalSection').classList.remove('d-none');
    }
  } catch (err) {
    console.error(err);
    alert('An error occurred while requesting approval.');
  }
});

// -------------- Admin Registration: Complete Registration --------------
document.getElementById('adminCompleteForm')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = document.getElementById('adminName').value.trim();
  const email = document.getElementById('adminEmail').value.trim();
  const password = document.getElementById('adminPassword').value;
  if (!name || !email || !password) {
    alert('All fields are required.');
    return;
  }
  try {
    const res = await fetch('/api/auth/admin/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, email, password })
    });
    const result = await res.json();
    const msgEl = document.getElementById('adminRegisterMessage');
    if (!res.ok) {
      msgEl.textContent = result.error || 'Admin registration failed.';
      msgEl.classList.add('error');
    } else {
      msgEl.textContent = result.message;
      msgEl.classList.remove('error');
      setTimeout(() => showSection('adminLogin'), 1500);
    }
  } catch (err) {
    console.error(err);
    alert('An error occurred during admin registration.');
  }
});

// -------------- Admin Login --------------
document.getElementById('adminLoginForm')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const data = Object.fromEntries(new FormData(e.target));
  try {
    const res = await fetch('/api/auth/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    const result = await res.json();
    const msgEl = document.getElementById('adminLoginMessage');
    if (!res.ok) {
      msgEl.textContent = result.error || 'Admin login failed.';
      msgEl.classList.add('error');
    } else {
      msgEl.textContent = 'Admin login successful!';
      msgEl.classList.remove('error');
      localStorage.setItem('adminToken', result.token);
      // Redirect to admin dashboard page if not already there
      if (!window.location.pathname.includes('admin-dashboard.html')) {
        window.location.href = 'admin-dashboard.html';
      } else {
        showSection('adminDashboard'); // Assuming this hides other sections
        loadAdminDashboard(); // Load data if already on the page
      }
    }
  } catch (err) {
    console.error(err);
    document.getElementById('adminLoginMessage').textContent = 'An error occurred during admin login.';
    document.getElementById('adminLoginMessage').classList.add('error');
  }
});

// -------------- Admin Dashboard: Load Users & Actions --------------
async function loadAdminDashboard() {
  const adminToken = localStorage.getItem('adminToken');
  const userListTableBody = document.getElementById('admin-user-list');
  const errorDisplay = document.getElementById('admin-user-list-error');

  if (!userListTableBody) { // Should not happen if on admin-dashboard.html
    console.error('Admin user list table body not found.');
    return;
  }

  // Clear previous content and errors
  userListTableBody.innerHTML = '';
  if (errorDisplay) {
    errorDisplay.textContent = '';
    errorDisplay.style.display = 'none';
  }

  if (!adminToken) {
    if (errorDisplay) {
      errorDisplay.textContent = 'Admin token not found. Please log in as admin.';
      errorDisplay.style.display = 'block';
    } else {
      alert('Admin token not found. Please log in as admin.');
    }
    // Optionally redirect to admin login page
    // window.location.href = 'admin-login.html'; // Or showSection('adminLogin') if it's a SPA section
    return;
  }

  try {
    const res = await fetch('/api/admin/users', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + adminToken }
    });
    const result = await res.json();

    if (!res.ok) {
      const errorMsg = result.error || `Error ${res.status}: Failed to load users.`;
      if (errorDisplay) {
        errorDisplay.textContent = errorMsg;
        errorDisplay.style.display = 'block';
      } else {
        alert(errorMsg);
      }
      if (res.status === 401 || res.status === 403) {
        // Token might be invalid or expired, redirect to login
        localStorage.removeItem('adminToken'); // Clear bad token
        // window.location.href = 'admin-login.html'; // Or showSection('adminLogin')
      }
      return;
    }

    if (!result.users || result.users.length === 0) {
      if (errorDisplay) {
        errorDisplay.textContent = 'No users found.';
        errorDisplay.style.display = 'block';
      } else {
        userListTableBody.innerHTML = '<tr><td colspan="4">No users found.</td></tr>';
      }
      return;
    }

    result.users.forEach(user => {
      const tr = document.createElement('tr');
      // Only ID, Name, Email, City are required by the task for display
      tr.innerHTML = `
        <td>${user.id}</td>
        <td>${user.name}</td>
        <td>${user.email}</td>
        <td>${user.city || 'N/A'}</td>
        <td>
          <button class="btn btn-danger btn-sm me-1" onclick="deleteUser(${user.id}, '${user.email}')">
            <i class="fa-solid fa-trash"></i> Delete
          </button>
          <button class="btn btn-warning btn-sm" onclick="blockUser(${user.id}, '${user.email}')">
            <i class="fa-solid fa-ban"></i> Block
          </button>
        </td>
      `;
      userListTableBody.appendChild(tr);
    });
  } catch (err) {
    console.error('Admin Dashboard Error:', err);
    const genericErrorMsg = 'An unexpected error occurred while loading dashboard data.';
    if (errorDisplay) {
      errorDisplay.textContent = genericErrorMsg;
      errorDisplay.style.display = 'block';
    } else {
      alert(genericErrorMsg);
    }
  }
}

// Load admin dashboard data if on the admin dashboard page
document.addEventListener('DOMContentLoaded', () => {
  // Check if we are on the admin-dashboard.html page
  // This can be done by checking for a specific element ID or the URL path
  if (document.getElementById('admin-user-list')) {
    loadAdminDashboard();
  }
});

// -------------- Admin Dashboard: Delete User --------------
function deleteUser(userId, userEmail) {
  const message = prompt("Enter custom message to send to the user upon deletion:");
  if (message === null) return;
  fetch('/api/admin/delete-user', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + localStorage.getItem('adminToken')
    },
    body: JSON.stringify({ userId, userEmail, message })
  })
    .then(res => res.json())
    .then(result => {
      alert(result.message || 'User deleted successfully.');
      loadAdminDashboard();
    })
    .catch(err => {
      console.error(err);
      alert('Error deleting user.');
    });
}

// -------------- Admin Dashboard: Block User --------------
function blockUser(userId, userEmail) {
  const message = prompt("Enter custom message to send to the user upon blocking:");
  if (message === null) return;
  fetch('/api/admin/block-user', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + localStorage.getItem('adminToken')
    },
    body: JSON.stringify({ userId, userEmail, message })
  })
    .then(res => res.json())
    .then(result => {
      alert(result.message || 'User blocked successfully.');
      loadAdminDashboard();
    })
    .catch(err => {
      console.error(err);
      alert('Error blocking user.');
    });
}

// -------------- Logout (Admin) --------------
function logoutAdmin() {
  localStorage.removeItem('adminToken');
  showSection('landing');
}
