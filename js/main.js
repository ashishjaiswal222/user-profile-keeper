// Utility: Show a section and hide others
function showSection(sectionId) {
  document.querySelectorAll('.section').forEach(sec => sec.classList.remove('active'));
  const activeSec = document.getElementById(sectionId);
  if (activeSec) activeSec.classList.add('active');
  // Update hash for SPA navigation, but avoid if it's the initial load to landing
  if (sectionId !== 'landing' || window.location.hash) {
    window.location.hash = sectionId;
  } else if (sectionId === 'landing' && window.location.hash) {
    // If navigating to landing and there's a hash, clear it.
    history.pushState("", document.title, window.location.pathname + window.location.search);
  }
}

// Comprehensive navigation update function
function updateNav() {
  const token = localStorage.getItem('token');
  const adminToken = localStorage.getItem('adminToken');

  // Get all nav items by their IDs
  const homeNav = document.getElementById('homeNav');
  const registerNav = document.getElementById('registerNav');
  const loginNav = document.getElementById('loginNav');
  const profileNav = document.getElementById('profileNav');
  const adminLoginNav = document.getElementById('adminLoginNav');
  const adminDashboardNav = document.getElementById('adminDashboardNav');
  const logoutNav = document.getElementById('logoutNav');

  // Ensure all elements exist before trying to set style
  if (!homeNav || !registerNav || !loginNav || !profileNav || !adminLoginNav || !adminDashboardNav || !logoutNav) {
    console.error("One or more navigation elements are missing from the DOM.");
    return;
  }

  // Default: Not Logged In
  homeNav.style.display = 'block';
  registerNav.style.display = 'block';
  loginNav.style.display = 'block';
  adminLoginNav.style.display = 'block';
  profileNav.style.display = 'none';
  adminDashboardNav.style.display = 'none';
  logoutNav.style.display = 'none';

  if (adminToken) { // Admin Logged In
    homeNav.style.display = 'block'; // Or 'none' if admin has a very specific view
    adminDashboardNav.style.display = 'block';
    logoutNav.style.display = 'block';

    registerNav.style.display = 'none';
    loginNav.style.display = 'none';
    profileNav.style.display = 'none'; // Hide regular user profile for admin
    adminLoginNav.style.display = 'none';
  } else if (token) { // User Logged In (Not Admin)
    homeNav.style.display = 'block';
    profileNav.style.display = 'block';
    logoutNav.style.display = 'block';

    registerNav.style.display = 'none';
    loginNav.style.display = 'none';
    adminLoginNav.style.display = 'none';
    adminDashboardNav.style.display = 'none';
  }
  // If neither adminToken nor token, the default visibility set above is correct.
}

// Generic Logout Function
function logout() {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
  localStorage.removeItem('adminToken');
  updateNav();
  showSection('login'); // Or 'landing'
}

// Function to show admin dashboard (checks auth and loads data)
function showAdminDashboard() {
  const adminToken = localStorage.getItem('adminToken');
  if (adminToken) {
    showSection('adminDashboard');
    loadAdminDashboard(); 
  } else {
    alert('Please log in as admin first.');
    showSection('adminLogin');
  }
  updateNav(); // Update nav based on current auth state
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
    updateNav(); // Update nav if token is missing
  } else {
    getUserProfile();
    showSection('profile');
    // updateNav(); // Not strictly necessary here if login/logout are the primary triggers
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
      updateNav(); // Update nav after successful user login
      setTimeout(() => {
        // getUserProfile(); // Called by handleProfileClick or when profile section is shown
        showSection('profile'); 
      }, 1500); // Delay can be removed if direct navigation is preferred
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

// -------------- Reset Password (SPA context) --------------
// This listener is for the #resetForm within index.html
const resetFormSPA = document.getElementById('resetForm');
if (resetFormSPA) {
  resetFormSPA.addEventListener('submit', async (e) => {
    e.preventDefault();
    const newPassword = document.getElementById('newPassword').value;
    const msgEl = document.getElementById('resetMessage'); // Message element within the #reset section
    
    const queryParams = getQueryParams(); // Get token and email from URL
    const token = queryParams.token;
    const email = queryParams.email;

    if (!token || !email) {
      msgEl.textContent = 'Missing token or email from URL. Please use the link from your email.';
      msgEl.classList.add('error');
      // Optionally, redirect to forgot password or login if params are missing
      // showSection('forgot'); 
      return;
    }

    if (!newPassword) {
      msgEl.textContent = 'Please enter a new password.';
      msgEl.classList.add('error');
      return;
    }
    msgEl.textContent = ''; 
    msgEl.classList.remove('error', 'success'); // Clear previous states

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
        msgEl.classList.add('success'); // Use a success class for styling if available
        msgEl.classList.remove('error');
        setTimeout(() => {
          showSection('login');
          // Clear URL parameters without full page reload, and ensure a hash for SPA behavior
          window.history.pushState({}, document.title, window.location.pathname + "#login");
          resetFormSPA.reset(); 
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
      // showAdminDashboard already calls updateNav
      showAdminDashboard(); 
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
  const userListTableBody = document.getElementById('adminUserTableBody'); // Corrected ID for index.html
  const errorDisplay = document.getElementById('adminDashboardError'); // Corrected ID for index.html

  if (!userListTableBody) { 
    console.error('Admin user table body (adminUserTableBody) not found.');
    if (errorDisplay) {
        errorDisplay.textContent = 'Admin dashboard UI elements are missing (table body). Please contact support.';
        errorDisplay.style.display = 'block';
    }
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
      // Fallback if errorDisplay itself is missing for some reason
      alert('Admin token not found. Please log in as admin.');
    }
    showSection('adminLogin'); // Redirect to admin login if not authenticated
    updateNav(); // Ensure nav is updated if token was expected but not found
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

    if (!result.users || !Array.isArray(result.users) || result.users.length === 0) {
      userListTableBody.innerHTML = ''; // Clear any existing rows
      const tr = document.createElement('tr');
      tr.innerHTML = '<td colspan="5" class="text-center fst-italic">No users currently registered.</td>';
      userListTableBody.appendChild(tr);
      if (errorDisplay) { // Clear any previous API errors
        errorDisplay.textContent = '';
        errorDisplay.style.display = 'none';
      }
      return;
    }
    // If users are found, ensure error display is hidden
    if (errorDisplay) {
        errorDisplay.textContent = '';
        errorDisplay.style.display = 'none';
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
          <button class="btn btn-danger btn-sm me-1" title="Delete User" onclick="deleteUser(${user.id}, '${user.email}')">
            <i class="fa-solid fa-trash"></i> Delete
          </button>
          <button class="btn btn-warning btn-sm" title="Block User" onclick="blockUser(${user.id}, '${user.email}')">
            <i class="fa-solid fa-ban"></i> Block
          </button>
        </td>
      `;
      userListTableBody.appendChild(tr);
    });
  } catch (err) {
    console.error('Admin Dashboard Error:', err);
    const genericErrorMsg = 'An unexpected error occurred while loading dashboard data. Please check your connection or try again later.';
    if (errorDisplay) {
      errorDisplay.textContent = genericErrorMsg;
      errorDisplay.style.display = 'block';
    } else {
      alert(genericErrorMsg);
    }
     // Also clear the table body in case of a full fetch error, to avoid showing stale data.
    userListTableBody.innerHTML = `<tr><td colspan="5" class="text-center text-danger">Error loading user data.</td></tr>`;
  }
}

// Initial setup on DOMContentLoaded (modified for SPA context)
document.addEventListener('DOMContentLoaded', () => {
  const queryParams = getQueryParams();
  let initialSection = window.location.hash.substring(1);

  if (initialSection === 'reset' && queryParams.token && queryParams.email) {
    showSection('reset');
  } else if (initialSection && document.getElementById(initialSection)) {
    showSection(initialSection); 
    if (initialSection === 'adminDashboard' && localStorage.getItem('adminToken')) {
      loadAdminDashboard();
    } else if (initialSection === 'adminDashboard' && !localStorage.getItem('adminToken')) {
      showSection('adminLogin'); 
    } else if (initialSection === 'profile' && localStorage.getItem('token')) {
      getUserProfile();
    } else if (initialSection === 'profile' && !localStorage.getItem('token')) {
      showSection('login');
    }
  } else {
    showSection('landing'); 
  }
  updateNav(); // Centralized nav update on load
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
  showSection('adminLogin'); // Or 'landing' as per preference
  updateAdminNavVisibility();
}
