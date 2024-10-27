const express = require('express');
const admin = require('firebase-admin');
const fetch = require('node-fetch');
const app = express();
const port = 4002;

// Inisialisasi Firebase Admin SDK
const serviceAccount = require('./serviceAccountKey.json');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: 'https://fir-api-42f33-default-rtdb.firebaseio.com/'
});

app.use(express.json());

// Endpoint untuk mendaftar pengguna
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Mendaftar pengguna baru
    const userRecord = await admin.auth().createUser({
      email: email,
      password: password,
    });

    // Membuat custom token
    const customToken = await admin.auth().createCustomToken(userRecord.uid);

    // Menukar custom token menjadi ID token
    const response = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=AIzaSyCSEddbNdyyXztHbPVXSHzc5PTdQgOCUCg`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: customToken, returnSecureToken: true })
      }
    );

    const data = await response.json();
    if (data.idToken) {
      // Mengirimkan ID token ke klien
      res.status(200).send({ token: data.idToken });
    } else {
      throw new Error('Failed to retrieve ID token');
    }
  } catch (error) {
    console.error('Error registering user:', error.message);
    res.status(500).send({ error: 'Error registering user: ' + error.message });
  }
});

// Middleware untuk memverifikasi token
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization && req.headers.authorization.split(' ')[1];

  if (!token) {
    return res.status(401).send({ message: 'No token provided' });
  }

  // Verifikasi ID token
  admin.auth().verifyIdToken(token)
    .then((decodedToken) => {
      req.uid = decodedToken.uid; // Menyimpan UID di request
      next(); // Melanjutkan ke middleware/route berikutnya
    })
    .catch((error) => {
      console.error('Error verifying token:', error.message);
      res.status(401).send({ error: 'Invalid token' });
    });
};

// Endpoint untuk memverifikasi ID token
app.post('/verify-token', (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).send({ message: 'Token harus disediakan' });
  }

  // Verifikasi ID token
  admin.auth().verifyIdToken(token)
    .then((decodedToken) => {
      const uid = decodedToken.uid;
      res.status(200).send({ message: 'Token valid', uid: uid });
    })
    .catch((error) => {
      console.error('Error verifying token: ', error.message);
      res.status(401).send({ error: 'Invalid token' });
    });
});

// Endpoint untuk mengambil semua data pengguna
app.get('/data', verifyToken, async (req, res) => {
  try {
    // Mengambil semua data dari Realtime Database
    const usersRef = admin.database().ref('users'); // Ganti 'users' sesuai dengan struktur database Anda
    const snapshot = await usersRef.once('value');

    const data = snapshot.val();

    if (data) {
      res.status(200).send({
        message: 'Data berhasil diambil',
        data: data // Kirimkan semua data pengguna yang diambil
      });
    } else {
      res.status(404).send({
        message: 'Data tidak ditemukan'
      });
    }
  } catch (error) {
    console.error('Error retrieving data:', error.message);
    res.status(500).send({ error: 'Terjadi kesalahan saat mengambil data' });
  }
});

// Jalankan server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
