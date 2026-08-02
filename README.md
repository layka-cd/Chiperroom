# CipherRoom — server real-time

Room chat real-time (bukan polling) pakai WebSocket (Socket.IO), dengan enkripsi
tetap dilakukan sepenuhnya di browser. Server ini cuma tukang antar amplop
tertutup — nggak pernah buka isinya, dan nggak pernah menyimpannya ke disk.

## Bagaimana keamanannya bekerja

Dari kode ruang yang kamu ketik, browser menurunkan **dua nilai berbeda**:

1. `roomId` — hash SHA-256 satu-arah dari kode ruang. Ini yang dikirim ke
   server, dipakai server cuma untuk tahu "siapa masuk channel yang mana".
   Karena SHA-256 satu arah, server tidak bisa membalikkannya jadi kode
   ruang aslinya.
2. `roomKey` — kunci AES-256-GCM, diturunkan lewat PBKDF2 (150.000 iterasi)
   dari kode ruang yang sama, tapi dengan "bumbu" (salt/context) yang
   berbeda dari yang dipakai untuk `roomId`. Kunci ini **tidak pernah
   meninggalkan browser**.

Jadi:
- Server tahu ada percakapan yang berlangsung dan siapa nama-nama yang gabung,
  tapi tidak bisa membaca isi pesannya.
- Kalau seseorang salah ketik kode ruang, dia gabung ke `roomId` yang beda
  (dan kalau kebetulan sama, kunci dekripsinya beda) — jadi otomatis tidak
  bisa membaca isi obrolan.
- Pesan hanya disimpan di memori (RAM) server selama ruang itu masih ada
  anggotanya, untuk keperluan "history sesi ini" bagi yang baru gabung.
  Begitu ruang kosong, buffer-nya dibuang. Tidak ada database, tidak ada
  file log pesan.

**Yang tidak dilindungi:** username (server melihatnya dalam bentuk asli,
untuk keperluan daftar anggota — sama seperti ipchat.in), waktu kirim, dan
metadata siapa terhubung ke room mana. Kalau kamu butuh username juga
tersembunyi dari server, itu perlu perubahan desain lebih lanjut (misalnya
menyiarkan presence lewat pesan terenkripsi juga, bukan lewat identitas
socket) — bisa saya bantu kalau kamu mau ke sana.

## Menjalankan di komputer sendiri

```bash
npm install
npm start
```

Lalu buka `http://localhost:3000`.

## Deploy ke publik (rekomendasi tercepat)

Pilih salah satu platform Node hosting gratis/murah — semuanya otomatis
kasih HTTPS/WSS jadi kamu tidak perlu urus sertifikat sendiri:

- **Render.com** — buat "Web Service" baru, hubungkan repo, build command
  `npm install`, start command `npm start`.
- **Railway.app** — deploy dari GitHub, otomatis deteksi Node lewat
  `package.json`.
- **Fly.io** — `fly launch` di folder ini, ikuti wizard-nya.

Setelah deploy, ganti baris `cors: { origin: "*" }` di `server.js` menjadi
domain aslimu, misalnya `origin: "https://cipherroom-kamu.onrender.com"`,
supaya cuma domain kamu sendiri yang boleh connect ke relay ini.

## Deploy ke VPS sendiri (kalau mau kontrol penuh)

1. `npm install --production` di server.
2. Jalankan dengan process manager supaya tetap hidup:
   ```bash
   npm install -g pm2
   pm2 start server.js --name cipherroom
   pm2 save
   ```
3. Pasang Nginx sebagai reverse proxy (biar bisa pakai domain + HTTPS/WSS):
   ```nginx
   server {
     listen 443 ssl;
     server_name chat.domainkamu.com;

     location / {
       proxy_pass http://127.0.0.1:3000;
       proxy_http_version 1.1;
       proxy_set_header Upgrade $http_upgrade;
       proxy_set_header Connection "upgrade";
       proxy_set_header Host $host;
     }
   }
   ```
4. Pakai `certbot --nginx` untuk sertifikat TLS gratis dari Let's Encrypt.
   Ini penting — tanpa HTTPS/WSS, koneksi antara browser dan server tidak
   terenkripsi di level transport, jadi enkripsi client-side jadi lapisan
   pertahanan satu-satunya.

## Batasan yang jujur perlu kamu tahu

- Rate limit dan batas anggota per ruang masih sederhana (di memori, per
  proses) — kalau nanti kamu scale ke banyak instance server sekaligus,
  ini perlu dipindah ke sesuatu seperti Redis supaya konsisten antar
  instance.
- Tidak ada autentikasi/akun — siapa pun yang tahu kode ruang bisa join,
  persis seperti model ipchat.in. Ini pilihan desain (kesederhanaan &
  anonimitas), bukan kelalaian — tapi berarti keamanan ruang murni
  bergantung pada seberapa rahasia kode ruangnya.
- Tidak ada verifikasi identitas sesama anggota (tidak ada "safety number"
  seperti Signal) — jadi tidak melindungi dari server yang jahat mengganti
  kunci di tengah jalan (man-in-the-middle di level aplikasi). Untuk
  obrolan santai ini cukup; untuk kebutuhan keamanan tinggi, pertimbangkan
  menambahkan verifikasi fingerprint kunci antar anggota.
