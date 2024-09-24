document.addEventListener('DOMContentLoaded', () => {
  const localhost = 'http://localhost:3000';  // Local backend
  const backendhost = 'http://3.36.98.23:80'; // Production backend over HTTP

  // Check if the current page is served locally (non-SSL), use HTTP, otherwise HTTPS
  const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
  const host = isLocal ? localhost : backendhost;

  // Dynamic socket connection based on environment
  const backendUrl = `${host}/chat`;

// const host = process.env.NODE_ENV === 'prod' ? backendhost : localhost
  console.log(`host name : ${window.location.hostname}`);
  // const host = window.location.hostname === '127.0.0.1'
  //   ? localhost
  //   : backendhost;
  // const host = 'localhost'
  console.log(`host : ${host}`);
  // const backendUrl = `${host}/chat`
  if (!window.socket) {
    // window.socket = io('http://3.36.98.23:80/chat'); // Connect to the chat namespace
    // window.socket = io('localhost:3000/chat');
    // Dynamically set the Socket.io server based on environment

      // Production backend URL
      // Local backend URL during development

    window.socket = io(backendUrl);
  }
  const socket = window.socket;
  console.log(`dom content loaded`);
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

  let currentUser = null;
  // let token = null;

  // Check if user is already logged in
  // checkLogin();
  checkSession();

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
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password }),
      });

      console.log(`response text : ${response.text}`);
      console.log(`response: ${JSON.stringify(response)}`);

      if (response.ok) {
        const data = await response.json();
        console.log('Sign up response:', data);
        currentUser = data.user;
        showMainContainer();
        await fetchAndDisplayFriends();
      } else {
        alert('Sign up failed');
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

    console.log(`email: ${email} password: ${password} `);

    try {
      console.log(`host: ${host}`);
      const response = await fetch(`${host}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      console.log(`Response status: ${response.status}`);
      console.log(`response text : ${response.text}`);

      if (response.ok) {
        const data = await response.json();
        // token = data.token;
        currentUser = data.user;
        console.log('Login response:', data);
        // currentUser = data.user;
        showMainContainer();
        await fetchAndDisplayFriends();
      } else {
        console.log(`response: ${JSON.stringify(response)}`);
        alert('Login failed');
      }
    } catch (error) {
      console.error('Error:', error);
      alert('Login failed');
    }
  });

  // Fetch and display friends list
  async function fetchAndDisplayFriends() {
    try {
      const response = await fetch(`${host}/users/friends`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      });

      if (response.ok) {
        const data = await response.json();
        console.log('Fetched friends data:', data);
        if (Array.isArray(data.friends)) {
          displayFriends(data.friends);
        } else {
          console.error('Expected an array of friends');
        }
        // token = data.token;
        // currentUser = data.user;
        // displayFriends(data.friends);
      } else {
        console.error('Failed to fetch friends');
      }
    } catch (error) {
      console.error('Error:', error);
    }
  }

  // Display friends list
  function displayFriends(friends) {
    if (!Array.isArray(friends)) {
      console.error('Friends list is not an array:', friends);
      return;
    }
    console.log(`display friends: ${friends}`);
    friendsList.innerHTML = '';
    friends.forEach((friend) => {
      const li = document.createElement('li');
      li.textContent = friend.username || friend.email;
      li.dataset.friendId = friend.id;
      friendsList.appendChild(li);
    });
  }

  async function checkSession() {
    console.log('Checking session');
    try {
      const response = await fetch(`${host}/auth/check-session`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      });

      if (response.ok) {
        const data = await response.json();
        currentUser = data.user;
        // showChatContainer();
        showMainContainer();
        await fetchAndDisplayFriends();
        // addSendMessageListener(); // Add listener here
      } else {
        showAuthContainer();
      }
    } catch (error) {
      console.error('Error:', error);
      showAuthContainer();
    }
  }

  // Logout
  logoutBtn.addEventListener('click', async () => {
    try {
      const response = await fetch(`${host}/auth/logout`, { method: 'POST' });
      if (response.ok) {
        currentUser = null;
        showAuthContainer();
      } else {
        alert('Logout failed');
      }
    } catch (error) {
      console.error('Error:', error);
      alert('Logout failed');
    }
  });

  // Add Friend
  addFriendForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const friendEmail = friendIdentifierInput.value;
    console.log(`Friend: ${friendEmail}`);

    try {
      const response = await fetch(`${host}/users/add-friend`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ friendEmail }),
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

  // Send Message
  function sendMessage() {
    const messageText = messageInput.value.trim();
    if (messageText === '') return;

    const roomId = chatContainer.dataset.roomId; // Assume roomId is set as a data attribute
    console.log(`client room id: ${roomId}`);
    if (!roomId) {
      console.error('Room ID not set on chat container');
      return;
    }

    const message = {
      roomId: parseInt(roomId, 10),
      content: messageText,
      userId: currentUser.id,
    };

    console.log('Sending message:', message); // Debug log
    socket.emit('sendMessage', message);

    // Update UI immediately
    // appendMessage(messageText, 'me');

    messageInput.value = '';
  }

  function appendMessage(messageText, senderType) {
    const messageElement = document.createElement('div');
    messageElement.classList.add('chat-message', senderType);

    const messageContent = document.createElement('div');
    messageContent.classList.add('message');
    messageContent.textContent = messageText;

    const timestamp = document.createElement('div');
    timestamp.classList.add('timestamp');
    timestamp.textContent = new Date().toLocaleTimeString();

    messageElement.appendChild(messageContent);

    messageElement.appendChild(timestamp);
    chatMessages.appendChild(messageElement);
    console.log(messageElement, messageContent, timestamp);

    chatMessages.scrollTop = chatMessages.scrollHeight;
  }

  // Display Message
  socket.on('newMessage', (message) => {
    console.log(`New message received: ${JSON.stringify(message)}`);
    const senderType = message.user.id === currentUser.id ? 'me' : 'other';
    appendMessage(message.content, senderType);
  });

  friendsList.addEventListener('click', async (e) => {
    if (e.target && e.target.tagName === 'LI') {
      const friendId = e.target.dataset.friendId;
      try {
        const response = await fetch(`${host}/rooms/find-or-create`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ friendId }),
        });
        if (response.ok) {
          console.log('ok and joinroom');
          const data = await response.json();
          chatContainer.dataset.roomId = data.roomId;
          socket.emit('joinRoom', { roomId: data.roomId });
          showChatContainer();
          await loadChatRoom(data.roomId);
        } else {
          alert('Failed to create or find room');
        }
      } catch (error) {
        console.error('Error:', error);
        alert('Failed to create or find room');
      }
    }
  });

  async function loadChatRoom(roomId) {
    try {
      const response = await fetch(`${host}/chat/rooms/${roomId}/logs`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      });
      console.log(`response: ${JSON.stringify(response)}`);
      if (response.ok) {
        const data = await response.json();
        chatMessages.innerHTML = '';
        chatContainer.dataset.roomId = roomId;
        data.messages.forEach((message) => {
          const senderType =
            message.user.id === currentUser.id ? 'me' : 'other';
          appendMessage(message.content, senderType);
        });
      } else {
        const errorText = await response.text(); // Read the response as text
        console.error('Failed to load chat room:', errorText);
        console.log(`error: ${errorText}`);
        alert('Failed to load chat room');
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
    try {
      const response = await fetch(`${host}/chat`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      });

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
