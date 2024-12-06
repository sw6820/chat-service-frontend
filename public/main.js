// Import the Socket.IO client library
import { io } from "https://cdn.socket.io/4.7.4/socket.io.esm.min.js";

document.addEventListener('DOMContentLoaded', () => {
  // import jwtDecode from 'jwt-decode';
  const localhost = 'http://localhost:3000';  // Local backend
  const backendhost = 'https://api.stahc.uk'; // Production backend over HTTP

  // Check if the current page is served locally (non-SSL), use HTTP, otherwise HTTPS
  const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
  const host = isLocal ? localhost : backendhost;
  console.log(`is local : ${isLocal}, host : ${host}`);
  // Dynamic socket connection based on environment
  const backendUrl = `${host}/chat`;

// const host = process.env.NODE_ENV === 'prod' ? backendhost : localhost
  console.log(`host name : ${window.location.hostname}`);
  // const host = window.location.hostname === '127.0.0.1'
  //   ? localhost
  //   : backendhost;
  // const host = 'localhost'
  console.log(`host : ${host}`);

  let socket;
  let currentUser = null;
  // {
  // const backendUrl = `${host}/chat`
  console.log(`current user : ${currentUser}`);
  // if (!window.socket) {
  // window.socket = io('http://3.36.98.23:80/chat'); // Connect to the chat namespace
  // window.socket = io('localhost:3000/chat');
  // Dynamically set the Socket.io server based on environment

  // Production backend URL
  // Local backend URL during development

  // window.socket = io(backendUrl);
  // console.log(`connecting to ${Object.keys(window.socket).io}`);
  // console.log(`connecting to ${window.socket.io}`)
  // }
  // const socket = window.socket;
  // console.log(`connecting to ${JSON.stringify(socket)}`);
  // console.log(`dom content loaded`);
// }
  // Auth elements
  const authContainer = document.getElementById('auth-container');
  const mainContainer = document.getElementById('main-container');
  const profileFriendsContainer = document.getElementById(
    'profile-friends-container',
  );
  const chatListContainer = document.getElementById('chat-list-container');
  const signupForm = document.getElementById('signup-form');
  const loginForm = document.getElementById('login-form');
  const profileBtn = document.getElementById('profileBtn');
  const chatListBtn = document.getElementById('chatListBtn');
  const logoutBtn = document.getElementById('logoutBtn');

  // const checkTokenBtn = document.getElementById('check-token-btn');

  // Chat elements
  const chatContainer = document.getElementById('chat-container');
  // const chatForm = document.getElementById('chatForm');
  const messageInput = document.getElementById('messageInput');
  const sendMessageBtn = document.getElementById('sendMessageBtn');
  const chatMessages = document.getElementById('chatMessages');

  const chatList = document.getElementById('chatList');

  // Friends elements
  const friendsList = document.getElementById('friends');
  const addFriendForm = document.getElementById('add-friend-form');
  const friendIdentifierInput = document.getElementById('friend-identifier');

  // Function to initialize socket connection
  function initializeSocket() {
    const token = localStorage.getItem('access_token');
    if (!token) {
      console.error('No access token found');
      return;
    }

    socket = io(backendUrl, {
        transports: ['websocket', 'polling'],  // Add polling as fallback
        auth: { token },
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000,
        timeout: 10000
    });

    // Add reconnect listeners
    socket.on('reconnect_attempt', () => {
        console.log('Attempting to reconnect...');
    });

        socket.on('reconnect', () => {
        console.log('Reconnected to server');
        // Rejoin the current room if any
        const currentRoomId = chatContainer.dataset.roomId;
        if (currentRoomId) {
            socket.emit('joinRoom', { roomId: currentRoomId });
        }
    });

    socket.on('connect_error', (error) => {
      console.error('Connection error:', error);
    });

    socket.on('disconnect', (reason) => {
      console.log('Disconnected:', reason);
    });

    // Add listener to confirm when a room is joined
    socket.on('roomJoined', (roomId) => {
      console.log('Successfully joined room:', roomId);
    });

    // Listen for new messages
    socket.on('newMessage', (message) => {
      console.log(`New message received: ${JSON.stringify(message)}`);
      const senderType = message.user.id === currentUser.userId ? 'me' : 'other';
      const formattedTime = formatMessageTime(message.createdAt);
      // console.log(`Formatted time: ${formattedTime}`);
      appendMessage(message.content, senderType, formattedTime);

    });
  }

  checkToken();
  console.log(`after check token current user : ${currentUser}`);

    // Add token refresh mechanism
  async function refreshToken() {
      try {
          const response = await fetch(`${host}/auth/refresh`, {
              method: 'POST',
              credentials: 'include'
          });
          
          if (response.ok) {
              const { access_token } = await response.json();
              localStorage.setItem('access_token', access_token);
              return true;
          }
          return false;
      } catch (error) {
          console.error('Token refresh failed:', error);
          return false;
      }
  }

  async function checkToken() {
    const token = localStorage.getItem('access_token');
    if (token) {
      try {
        console.log('Checking token validity');
        const response = await fetch(`${host}/auth/check-token`, {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${token}`,  // Send JWT token in the Authorization header
            'Content-Type': 'application/json',
          },
          credentials: 'include',
        });

        if (response.status === 401) {
            // Token expired, try to refresh
            const refreshed = await refreshToken();
            if (!refreshed) {
                throw new Error('Token refresh failed');
            }
            // Retry with new token
            return checkToken();
        }

        console.log(`Token check response status: ${response.status}`);

        if (response.ok) {
          const data = await response.json();
          console.log('Token is valid. User data:', data);
          currentUser = data.user;
          console.log(`current user after check token&response.ok ${JSON.stringify(currentUser)}`);
          showMainContainer();
          await fetchAndDisplayFriends();
          initializeSocket();
        } else {
          // Token might be invalid or expired, handle it here
          console.error('Token invalid or expired');
          localStorage.removeItem('access_token');
          showAuthContainer();
        }
      } catch (error) {
        console.error('Error:', error);
        localStorage.removeItem('access_token');
        showAuthContainer();
      }
    } else {
      console.log('No token found, showing auth container');
      showAuthContainer();  // If no token exists, show login/signup
      return;
    }
  }

  // Update fetch headers with consistent security headers
const defaultHeaders = {
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest'
};

// Update your fetch calls to use these headers
async function fetchWithAuth(url, options = {}) {
    const token = localStorage.getItem('access_token');
    const headers = {
        ...defaultHeaders,
        ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
        ...options.headers
    };

    return fetch(url, {
        ...options,
        headers,
        credentials: 'include'
    });
}

  // Sign Up
  signupForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    console.log(`sign up`);
    const username = document.getElementById('signup-username').value;
    const email = document.getElementById('signup-email').value;
    const password = document.getElementById('signup-password').value;

    console.log(`email: ${email} password: ${password} user: ${username}`);

    try {
      console.log(`host: ${host}`);
      const response = await fetch(`${host}/auth/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ username, email, password }),
        credentials: 'include',
        mode: 'cors',
      });

      // Get the token from Authorization header
      const authHeader = response.headers.get('Authorization');
      if (authHeader) {
        const token = authHeader.replace('Bearer ', '');
        console.log('Token from header:', token);
      }

      console.log(`response text : ${response.text}`);
      console.log(`response: ${JSON.stringify(response)}`);

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      console.log('Sign up response:', data);
      currentUser = data.user;
      const { access_token } = data;
      if (access_token) {
        localStorage.setItem('access_token', access_token);
        console.log('Access token stored in localStorage');
        try {
          const decodedToken = jwt_decode(access_token);
          console.log(`decoded token: ${decodedToken}`);
          currentUser = {
            userId: decodedToken.sub, // 'sub' is typically used for userId in JWT
            email: decodedToken.email,
            username: decodedToken.username
          };
          console.log(`current user after sign up : ${currentUser}`);
          showMainContainer();
          await fetchAndDisplayFriends();
          initializeSocket();
        } catch (error) {
          console.error('Error with jwt_decode:', error);
        }
      } else {
        console.error('Access token not found in response');
        alert('Login failed: No access token received');
      }                
    } catch (error) {
      console.error('Error:', error);
      alert('Sign up failed');
    }
  });

  // Login
  loginForm.addEventListener('submit', async (e) => {
    console.log('login');
    e.preventDefault();
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    console.log(`Attempting login for email: ${email}`);

    console.log(`email: ${email} password: ${password} `);

    try {
      console.log(`Sending login request to: ${host}/auth/login`);
      const response = await fetch(`${host}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',  // Add this header
          'Accept': 'application/json'
        },
        body: JSON.stringify({ email, password }),
        credentials: 'include',
        mode: 'cors',
      });
      console.log(`Response status: ${response.status}`);
      console.log(`response text : ${response.text}`);
      console.log(`res keys : ${Object.keys(response)}`);
      console.log(`response body : ${JSON.stringify(response)}`);
      console.log(`response headers : ${JSON.stringify(response.headers)}`);
      console.log(`response body : ${response}`);
      console.log('Response headers:', [...response.headers.entries()]);

      // Get the token from Authorization header
      const authHeader = response.headers.get('Authorization');
      if (authHeader) {
        const token = authHeader.replace('Bearer ', '');
        console.log('Token from header:', token);
      }

      let data;
      try {
        data = await response.json();
      } catch (e) {
        console.error('Failed to parse response as JSON:', e);
      }
      console.log(`after login, response data : ${JSON.stringify(data)}`);

      if (!response.ok) {
        console.error('Login failed:', data.message || 'Unknown error');
        alert(`Login failed: ${data.message || 'Unknown error'}`);
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      if (response.ok) {
        console.log('Login response:', data);
        console.log('Login response data:', data);

        // currentUser = data.user;
        // const { access_token } = data;
        if (data.access_token) {
          localStorage.setItem('access_token', data.access_token);
          console.log('Access token stored in localStorage');
          // Decode the JWT token to get user information
          // const decodedToken = jwt_decode(access_token);
          try {
            const decodedToken = jwt_decode(data.access_token);
            console.log(`decoded token: ${decodedToken}`);
            currentUser = {
              userId: decodedToken.sub, // 'sub' is typically used for userId in JWT
              email: decodedToken.email,
              username: decodedToken.username
            };
            console.log('Current user after login:', currentUser);
            console.log('Login successful:', {
              user: currentUser,
              token: data.access_token
            });
            showMainContainer();
            await fetchAndDisplayFriends();
            initializeSocket();
          } catch (error) {
            console.error('Error with jwt_decode:', error);
          }
        } else {
          console.error('Access token not found in response');
          alert('Login failed: No access token received');
          throw new Error(data.message || 'Login failed');
          // Store the token in localStorage or a cookie if not using HTTP-only cookies
        }
      } else {

        // console.log(`response: ${JSON.stringify(response)}`);
        // alert('Login failed');
      }
    } catch (error) {
      console.error('Error:', error);
      alert(error.message || 'Login failed. Please try again.');
    }
  });

  async function authenticatedFetch(url, options = {}) {
    const token = localStorage.getItem('access_token');
    
    // Merge the authorization header with existing options
    const headers = {
      ...options.headers,
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    };

    // Make the request with credentials and merged options
    const response = await fetch(url, {
      ...options,
      headers,
      credentials: 'include'  // Always include credentials
    });

    // Handle 401 Unauthorized errors
    if (response.status === 401) {
      // Token might be expired - redirect to login
      localStorage.removeItem('access_token');
      window.location.href = '/login.html';  // Adjust path as needed
      throw new Error('Authentication failed');
    }

    return response;
  }

  // Use it like this:
  async function fetchAndDisplayFriends() {
    try {
      const response = await authenticatedFetch(`${host}/friends`);
      const friends = await response.json();
      // Handle friends data...
    } catch (error) {
      console.error('Error fetching friends:', error);
    }
  }  

  // Fetch and display friends list
  async function fetchAndDisplayFriends() {
    console.log(`display friends`);
    try {
      const token = localStorage.getItem('access_token'); // Get token from localStorage
      if (!token) {
        console.error('No access token found');
        showAuthContainer();
        return;
      }
      const response = await fetch(`${host}/users/friends`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json' },
        credentials: 'include',

      });
      console.log(`response: ${JSON.stringify(response)}`);
      console.log(`Friends response status: ${response.status}`);
      if (response.ok) {
        const data = await response.json();
        console.log('Fetched friends data:', data);
        if (Array.isArray(data.friends)) {
          displayFriends(data.friends);
        } else {
          console.error('Expected an array of friends');
        }
      } else {
        if (response.status === 401) {
          console.error('Unauthorized: Token may be invalid');
          localStorage.removeItem('access_token');
          showAuthContainer();
        } else {
          console.error('Failed to fetch friends');
        }
      }
    } catch (error) {
      console.error('Error fetching friends:', error);
    }
  }

  // Display friends list
  function displayFriends(friends) {
    if (!Array.isArray(friends)) {
      console.error('Friends list is not an array:', friends);
      return;
    }
    console.log(`display friends: ${JSON.stringify(friends)}`);
    friendsList.innerHTML = '';
    friends.forEach((friend) => {
      const li = document.createElement('li');
      li.textContent = friend.username || friend.email;
      li.dataset.friendId = friend.id;
      friendsList.appendChild(li);
    });
  }

  // async function checkSession() {
  //   console.log('Checking session');
  //   try {
  //     const response = await fetch(`${host}/auth/check-session`, {
  //       method: 'GET',
  //       headers: { 'Content-Type': 'application/json' },
  //     });
  //     console.log(`response : ${JSON.stringify(response)}`);
  //
  //     if (response.ok) {
  //       const data = await response.json();
  //       currentUser = data.user;
  //       showChatContainer();
  //       console.log(`response data : ${data}`)
  //       console.log('show main container');
  //       showMainContainer();
  //       console.log('fetch and display friends;')
  //       await fetchAndDisplayFriends();
  //       addSendMessageListener(); // Add listener here
  //     } else {
  //       showAuthContainer();
  //     }
  //   } catch (error) {
  //     console.error('Error:', error);
  //     showAuthContainer();
  //   }
  // }

  // Logout
  logoutBtn.addEventListener('click', async () => {
    try {
      const response = await fetch(`${host}/auth/logout`, {
        method: 'POST',
        credentials: 'include',
      });
      if (response.ok) {
        localStorage.removeItem('access_token');
        currentUser = null;
        if (socket) {
          socket.disconnect();
        }
        showAuthContainer();
      } else {
        alert('Logout failed');
      }
    } catch (error) {
      console.error('Logout Error:', error);
      alert('Logout failed');
    }
  });

  // Add Friend
  addFriendForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const friendEmail = friendIdentifierInput.value;
    console.log(`Friend: ${friendEmail}`);

    try {
      const token = localStorage.getItem('access_token');
      if (!token) {
        console.error('No access token found');
        showAuthContainer();
        return;
      }
      const response = await fetch(`${host}/users/add-friend`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ friendEmail }),
        credentials: 'include',
      });
      console.log(`res : ${JSON.stringify(response)}`);
      if (response.ok) {
        const data = await response.json();
        console.log(`res friend : ${JSON.stringify(data)}`);
        if (Array.isArray(data.friends)) {
          displayFriends(data.friends);
        } else {
          console.error('Expected an array of friends');
        }
      } else {
        alert('Add friend failed');
      }
    } catch (error) {
      console.error('Error:', error);
      alert('Add friend failed');
    }
  });

  // Show Main Container
  function showMainContainer() {
    authContainer.style.display = 'none';
    mainContainer.style.display = 'block';
    profileFriendsContainer.style.display = 'block';
    chatListContainer.style.display = 'none';
    chatContainer.style.display = 'none';
  }

  // Show Chat Container
  function showChatContainer() {
    authContainer.style.display = 'none';
    mainContainer.style.display = 'none';
    chatContainer.style.display = 'block';
  }

  // Show Auth Container
  function showAuthContainer() {
    mainContainer.style.display = 'none';
    chatContainer.style.display = 'none';
    authContainer.style.display = 'block';
  }

  // Add Event Listener for Send Message
  sendMessageBtn.addEventListener('click', sendMessage);
  messageInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      sendMessage();
      console.log('call sendMessage');
    }
  });

  // Add rate limiting for message sending
  const messageRateLimit = {
      lastMessage: 0,
      minInterval: 500, // Minimum time between messages in ms
  };

  function canSendMessage() {
      const now = Date.now();
      if (now - messageRateLimit.lastMessage < messageRateLimit.minInterval) {
          return false;
      }
      messageRateLimit.lastMessage = now;
      return true;
  }
    
  // Send Message
  function sendMessage() {
    if (!canSendMessage()) {
        console.log('Please wait before sending another message');
        return;
    }

    const messageText = messageInput.value.trim();
    console.log(`msg text: ${messageText}`);
    if (!messageText) return;

    const roomId = chatContainer.dataset.roomId; // Assume roomId is set as a data attribute
    console.log(`client room id: ${roomId}`);
    if (!roomId) {
        console.error('No room ID found');
        alert('Please select a chat room first');
        return;
    }

    if (!socket?.connected) {
        console.error('Socket disconnected');
        alert('Connection lost. Attempting to reconnect...');
        socket?.connect();
        return;
    }

    const message = {
      roomId: parseInt(roomId, 10),
      content: messageText,
      userId: currentUser.id,
      timestamp: new Date().toISOString(),
    };

    console.log('Sending message(debug):', message); // Debug log
    
    // Clear input before sending to improve perceived performance
    messageInput.value = '';
    socket.emit('sendMessage', message, (error) => {
      if (error) {
        console.error('Error sending message:', error);
        alert('Failed to send message. Please try again.');
        messageInput.value = message.content;
      } else {
        console.log('Message sent successfully');
        // Update UI immediately
      }
    });
    // Update UI immediately
  }

  function appendMessage(messageText, senderType, messageTime) {
    console.log(`after append message ${messageText} ${senderType} ${messageTime}`);
    const messageElement = document.createElement('div');
    messageElement.classList.add('chat-message', senderType);

    const messageContent = document.createElement('div');
    messageContent.classList.add('message');
    messageContent.textContent = messageText;

    const timestamp = document.createElement('div');
    timestamp.classList.add('timestamp');
    timestamp.textContent = messageTime;//.toLocaleTimeString();
    console.log(`message time type : ${typeof messageTime}`);
    messageElement.appendChild(messageContent);
    messageElement.appendChild(timestamp);
    chatMessages.appendChild(messageElement);
    console.log(messageElement, messageContent, timestamp);

    chatMessages.scrollTop = chatMessages.scrollHeight;
  }

  // Display Message
  friendsList.addEventListener('click', async (e) => {
    if (e.target && e.target.tagName === 'LI') {
      console.log(`dataset : ${Object.keys(e.target.dataset)}`);
      console.log(`friend id : ${ e.target.dataset.friendId}`);
      const friendId = e.target.dataset.friendId;
      if (isNaN(friendId)) {
        console.error('Invalid friendId:', e.target.dataset.friendId);
        alert('Invalid friend selected');
        return;
      }
      try {
        const token = localStorage.getItem('access_token');
        if (!token) {
          console.error('No access token found');
          alert('You are not logged in. Please log in and try again.');
          return;
        }
        const response = await fetch(`${host}/rooms/find-or-create`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ friendId }),
          credentials: 'include',
        });
        if (response.ok) {
          console.log('ok and joinroom');
          const data = await response.json();
          chatContainer.dataset.roomId = data.roomId;
          socket.emit('joinRoom', { roomId: data.roomId });
          showChatContainer();
          await loadChatRoom(data.roomId);
        } else {
          const errorData = await response.json().catch(() => ({}));
          console.error('Failed to create or find room:', response.status, errorData);
          alert(`Failed to create or find room: ${errorData.message || response.statusText}`);
        }
      } catch (error) {
        console.error('Error:', error);
        alert('Failed to create or find room');
      }
    }
  });

  function formatMessageTime(dateString) {
    const date = new Date(dateString);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  async function loadChatRoom(roomId) {
    try {
      const token = localStorage.getItem('access_token');
      if (!token) {
        console.error('No access token found');
        alert('You are not logged in. Please log in and try again.');
        showAuthContainer();
        return;
      }
      const response = await fetch(`${host}/chat/rooms/${roomId}/logs`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        credentials: 'include',
      });
      console.log(`Load chat room response status: ${response.status}`);
      console.log(`response: ${JSON.stringify(response)}`);
      if (response.ok) {
        const data = await response.json();
        console.log('Room created:', data.roomId);
        console.log(`data in chat room response ${JSON.stringify(data)}`)

        chatMessages.innerHTML = '';
        chatContainer.dataset.roomId = roomId;

        data.messages.forEach((message) => {
          console.log(`message : ${JSON.stringify(message)}`)
          console.log(`currentUser : ${JSON.stringify(currentUser)}`)
          const senderType =
            message.user.id === currentUser.userId ? 'me' : 'other';
          const formattedTime = formatMessageTime(message.createdAt);
          console.log(`Formatted time: ${formattedTime}`);
          appendMessage(message.content, senderType, formattedTime);
        });
      } else {
        if (response.status === 401) {
          console.error('Unauthorized: Token may be invalid');
          localStorage.removeItem('access_token');
          showAuthContainer();
        } else {
          console.error('Failed to load chat room');
          alert('Failed to load chat room');
        }
      }
    } catch (error) {
      console.log(`error loading chat ${error}`);
      console.error('Error:', error);
      alert('Failed to load chat room');
    }
  }

  // Toggle between Profile & Friends and Chat List
  profileBtn.addEventListener('click', () => {
    profileFriendsContainer.style.display = 'block';
    chatListContainer.style.display = 'none';
  });

  chatListBtn.addEventListener('click', async () => {
    profileFriendsContainer.style.display = 'none';
    chatListContainer.style.display = 'block';
    await fetchAndDisplayChats();
  });

  // Fetch and display chat list
  async function fetchAndDisplayChats() {
    console.log('Fetching chat list');
    try {
      const response = await fetch(`${host}/chat`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
      });
      console.log(`Response ${ JSON.stringify(response) }`);
      if (response.ok) {
        const data = await response.json();
        displayChats(data.chats);
      } else {
        console.error('Failed to fetch chats');
      }
    } catch (error) {
      console.error('Error:', error);
    }
  }

  // Display chat list
  function displayChats(chats) {
    chatList.innerHTML = '';
    chats.forEach((chat) => {
      const li = document.createElement('li');
      li.textContent = chat.name;
      chatList.appendChild(li);
    });
  }
});
