<?php
/**
 * Local Bitcoin message-signature verification for TOKENLOCK self-verify (spec v1). Needs the GMP extension.
 * Accepts what the hosted TOKENLOCK check accepts (shared vectors: test/fixtures/wallet-sig-vectors.json):
 *   - BIP-322 "simple" (the to_sign witness stack) and "full" (the whole to_sign transaction, accepted only when it is
 *     exactly the BIP-322 template for this address and message) for P2WPKH (bc1q…), P2SH-P2WPKH (3…) and single-key
 *     P2TR (bc1p…). ECDSA witnesses must be low-S.
 *   - legacy "Bitcoin Signed Message" (BIP-137 / Electrum, 65 bytes, header 27-42) for P2PKH, P2SH-P2WPKH, P2WPKH and
 *     P2TR (BIP-86 tweak of the recovered key); the header's address-type flag is ignored, like the hosted check.
 *   - the exact message first, then only its LF<->CRLF equivalent (Freewallet signs the CRLF form of an LF challenge).
 *   - signature encodings: ASCII whitespace removed, then strict base64, else even-length hex with an optional 0x.
 * Also BIP-340 Schnorr verification (used for signed policy bundles). No network calls.
 */
if (defined('TOKENLOCK_BTCSIG')) {
    return;
}
define('TOKENLOCK_BTCSIG', 1);

final class TokenlockSecp
{
    public static $p, $n, $gx, $gy, $ready = false;

    public static function init()
    {
        if (self::$ready) {
            return;
        }
        if (!extension_loaded('gmp')) {
            throw new RuntimeException('TOKENLOCK self-verify needs the PHP GMP extension (php-gmp).');
        }
        self::$p = gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 16);
        self::$n = gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16);
        self::$gx = gmp_init('79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798', 16);
        self::$gy = gmp_init('483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8', 16);
        self::$ready = true;
    }

    public static function G()
    {
        self::init();
        return array(self::$gx, self::$gy);
    }

    private static function mod($a, $m)
    {
        $r = gmp_mod($a, $m);
        return gmp_cmp($r, 0) < 0 ? gmp_add($r, $m) : $r;
    }

    // Jacobian coordinates: array(X, Y, Z); null = point at infinity.
    private static function jdouble($P)
    {
        if ($P === null || gmp_cmp($P[1], 0) === 0) {
            return null;
        }
        $p = self::$p;
        list($X, $Y, $Z) = $P;
        $YY = gmp_mod(gmp_mul($Y, $Y), $p);
        $S = gmp_mod(gmp_mul(4, gmp_mul($X, $YY)), $p);
        $M = gmp_mod(gmp_mul(3, gmp_mul($X, $X)), $p);
        $X3 = self::mod(gmp_sub(gmp_mul($M, $M), gmp_mul(2, $S)), $p);
        $Y3 = self::mod(gmp_sub(gmp_mul($M, gmp_sub($S, $X3)), gmp_mul(8, gmp_mul($YY, $YY))), $p);
        $Z3 = gmp_mod(gmp_mul(2, gmp_mul($Y, $Z)), $p);
        return array($X3, $Y3, $Z3);
    }

    private static function jadd($P, $Q)
    {
        if ($P === null) {
            return $Q;
        }
        if ($Q === null) {
            return $P;
        }
        $p = self::$p;
        list($X1, $Y1, $Z1) = $P;
        list($X2, $Y2, $Z2) = $Q;
        $Z1Z1 = gmp_mod(gmp_mul($Z1, $Z1), $p);
        $Z2Z2 = gmp_mod(gmp_mul($Z2, $Z2), $p);
        $U1 = gmp_mod(gmp_mul($X1, $Z2Z2), $p);
        $U2 = gmp_mod(gmp_mul($X2, $Z1Z1), $p);
        $S1 = gmp_mod(gmp_mul($Y1, gmp_mul($Z2, $Z2Z2)), $p);
        $S2 = gmp_mod(gmp_mul($Y2, gmp_mul($Z1, $Z1Z1)), $p);
        if (gmp_cmp($U1, $U2) === 0) {
            return gmp_cmp($S1, $S2) === 0 ? self::jdouble($P) : null;
        }
        $H = self::mod(gmp_sub($U2, $U1), $p);
        $R = self::mod(gmp_sub($S2, $S1), $p);
        $HH = gmp_mod(gmp_mul($H, $H), $p);
        $HHH = gmp_mod(gmp_mul($H, $HH), $p);
        $V = gmp_mod(gmp_mul($U1, $HH), $p);
        $X3 = self::mod(gmp_sub(gmp_sub(gmp_mul($R, $R), $HHH), gmp_mul(2, $V)), $p);
        $Y3 = self::mod(gmp_sub(gmp_mul($R, gmp_sub($V, $X3)), gmp_mul($S1, $HHH)), $p);
        $Z3 = gmp_mod(gmp_mul($H, gmp_mul($Z1, $Z2)), $p);
        return array($X3, $Y3, $Z3);
    }

    private static function toAffine($J)
    {
        if ($J === null) {
            return null;
        }
        $p = self::$p;
        $zi = gmp_invert($J[2], $p);
        $zi2 = gmp_mod(gmp_mul($zi, $zi), $p);
        return array(gmp_mod(gmp_mul($J[0], $zi2), $p), gmp_mod(gmp_mul($J[1], gmp_mul($zi2, $zi)), $p));
    }

    /** k1*A + k2*B (affine in/out, null = infinity). */
    public static function mul2($k1, $A, $k2 = null, $B = null)
    {
        self::init();
        $JA = $A === null ? null : array($A[0], $A[1], gmp_init(1));
        $JB = $B === null ? null : array($B[0], $B[1], gmp_init(1));
        $JAB = ($JA !== null && $JB !== null) ? self::jadd($JA, $JB) : null;
        $b1 = gmp_strval($k1, 2);
        $b2 = $k2 === null ? '0' : gmp_strval($k2, 2);
        $len = max(strlen($b1), strlen($b2));
        $b1 = str_pad($b1, $len, '0', STR_PAD_LEFT);
        $b2 = str_pad($b2, $len, '0', STR_PAD_LEFT);
        $R = null;
        for ($i = 0; $i < $len; $i++) {
            $R = self::jdouble($R);
            $x = $b1[$i] === '1';
            $y = $b2[$i] === '1';
            if ($x && $y) {
                $R = self::jadd($R, $JAB);
            } elseif ($x) {
                $R = self::jadd($R, $JA);
            } elseif ($y) {
                $R = self::jadd($R, $JB);
            }
        }
        return self::toAffine($R);
    }

    public static function onCurve($P)
    {
        $p = self::$p;
        return $P !== null && gmp_cmp(gmp_mod(gmp_sub(gmp_mul($P[1], $P[1]), gmp_add(gmp_pow($P[0], 3), 7)), $p), 0) === 0;
    }

    /** Point with this x and y parity (0 = even); null if x is not on the curve. */
    public static function liftX($x, $odd = 0)
    {
        self::init();
        $p = self::$p;
        if (gmp_cmp($x, 0) < 0 || gmp_cmp($x, $p) >= 0) {
            return null;
        }
        $c = gmp_mod(gmp_add(gmp_powm($x, 3, $p), 7), $p);
        $y = gmp_powm($c, gmp_div_q(gmp_add($p, 1), 4), $p);
        if (gmp_cmp(gmp_powm($y, 2, $p), $c) !== 0) {
            return null;
        }
        if ((int) gmp_intval(gmp_mod($y, 2)) !== ($odd ? 1 : 0)) {
            $y = gmp_sub($p, $y);
        }
        return array($x, $y);
    }

    public static function parsePub($bytes)
    {
        self::init();
        $l = strlen($bytes);
        if ($l === 33 && ($bytes[0] === "\x02" || $bytes[0] === "\x03")) {
            return self::liftX(self::int(substr($bytes, 1)), $bytes[0] === "\x03" ? 1 : 0);
        }
        if ($l === 65 && $bytes[0] === "\x04") {
            $P = array(self::int(substr($bytes, 1, 32)), self::int(substr($bytes, 33, 32)));
            return self::onCurve($P) ? $P : null;
        }
        return null;
    }

    public static function int($bytes)
    {
        return gmp_init(bin2hex($bytes) === '' ? '0' : bin2hex($bytes), 16);
    }

    public static function bytes32($n)
    {
        return hex2bin(str_pad(gmp_strval($n, 16), 64, '0', STR_PAD_LEFT));
    }

    public static function compressed($P)
    {
        return (gmp_intval(gmp_mod($P[1], 2)) ? "\x03" : "\x02") . self::bytes32($P[0]);
    }

    public static function uncompressed($P)
    {
        return "\x04" . self::bytes32($P[0]) . self::bytes32($P[1]);
    }

    /** ECDSA verify (no low-S rule, like the hosted check). */
    public static function ecdsaVerify($r, $s, $hash, $Q)
    {
        self::init();
        $n = self::$n;
        if (gmp_cmp($r, 1) < 0 || gmp_cmp($r, $n) >= 0 || gmp_cmp($s, 1) < 0 || gmp_cmp($s, $n) >= 0) {
            return false;
        }
        $e = gmp_mod(self::int($hash), $n);
        $w = gmp_invert($s, $n);
        $X = self::mul2(gmp_mod(gmp_mul($e, $w), $n), self::G(), gmp_mod(gmp_mul($r, $w), $n), $Q);
        return $X !== null && gmp_cmp(gmp_mod($X[0], $n), $r) === 0;
    }

    /** Public key from a recoverable signature (recid 0..3); null if none. */
    public static function recover($r, $s, $recid, $hash)
    {
        self::init();
        $n = self::$n;
        if (gmp_cmp($r, 1) < 0 || gmp_cmp($r, $n) >= 0 || gmp_cmp($s, 1) < 0 || gmp_cmp($s, $n) >= 0) {
            return null;
        }
        $x = $recid & 2 ? gmp_add($r, $n) : $r;
        $R = self::liftX($x, $recid & 1);
        if ($R === null) {
            return null;
        }
        $e = gmp_mod(self::int($hash), $n);
        $ri = gmp_invert($r, $n);
        // Q = r^-1 (sR - eG)
        $Q = self::mul2(gmp_mod(gmp_mul($s, $ri), $n), $R, self::mod(gmp_neg(gmp_mul($e, $ri)), $n), self::G());
        return $Q;
    }

    /** BIP-340 verify: 64-byte sig, 32-byte message, 32-byte x-only key. */
    public static function schnorrVerify($sig, $msg, $pub)
    {
        self::init();
        if (strlen($sig) !== 64 || strlen($pub) !== 32) {
            return false;
        }
        $P = self::liftX(self::int($pub), 0);
        if ($P === null) {
            return false;
        }
        $r = self::int(substr($sig, 0, 32));
        $s = self::int(substr($sig, 32));
        if (gmp_cmp($r, self::$p) >= 0 || gmp_cmp($s, self::$n) >= 0) {
            return false;
        }
        $e = gmp_mod(self::int(tokenlock_tagged_hash('BIP0340/challenge', substr($sig, 0, 32) . $pub . $msg)), self::$n);
        $R = self::mul2($s, self::G(), self::mod(gmp_neg($e), self::$n), $P);
        if ($R === null || gmp_intval(gmp_mod($R[1], 2)) !== 0) {
            return false;
        }
        return gmp_cmp($R[0], $r) === 0;
    }

    /** BIP-86 key-path tweak: x-only output key for an x-only internal key; null if invalid. */
    public static function tweakTaproot($xonly)
    {
        self::init();
        $t = self::int(tokenlock_tagged_hash('TapTweak', $xonly));
        if (gmp_cmp($t, self::$n) >= 0) {
            return null;
        }
        $P = self::liftX(self::int($xonly), 0);
        if ($P === null) {
            return null;
        }
        $Q = self::mul2(gmp_init(1), $P, $t, self::G());
        return $Q === null ? null : self::bytes32($Q[0]);
    }
}

function tokenlock_tagged_hash($tag, $msg)
{
    $t = hash('sha256', $tag, true);
    return hash('sha256', $t . $t . $msg, true);
}

function tokenlock_dsha($b)
{
    return hash('sha256', hash('sha256', $b, true), true);
}

function tokenlock_hash160($b)
{
    return hash('ripemd160', hash('sha256', $b, true), true);
}

function tokenlock_varint($n)
{
    if ($n < 0xfd) {
        return chr($n);
    }
    if ($n <= 0xffff) {
        return "\xfd" . pack('v', $n);
    }
    return "\xfe" . pack('V', $n);
}

function tokenlock_b58check_decode($s)
{
    $A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    if ($s === '' || strlen($s) > 60) {
        return null;
    }
    $n = gmp_init(0);
    for ($i = 0; $i < strlen($s); $i++) {
        $v = strpos($A, $s[$i]);
        if ($v === false) {
            return null;
        }
        $n = gmp_add(gmp_mul($n, 58), $v);
    }
    $hex = gmp_cmp($n, 0) === 0 ? '' : gmp_strval($n, 16);
    if (strlen($hex) % 2) {
        $hex = '0' . $hex;
    }
    $b = $hex === '' ? '' : hex2bin($hex);
    for ($i = 0; $i < strlen($s) && $s[$i] === '1'; $i++) {
        $b = "\x00" . $b;
    }
    if (strlen($b) < 5) {
        return null;
    }
    $body = substr($b, 0, -4);
    return substr(tokenlock_dsha($body), 0, 4) === substr($b, -4) ? $body : null;
}

function tokenlock_bech32_polymod($values)
{
    $G = array(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3);
    $chk = 1;
    foreach ($values as $v) {
        $top = $chk >> 25;
        $chk = (($chk & 0x1ffffff) << 5) ^ $v;
        for ($i = 0; $i < 5; $i++) {
            if (($top >> $i) & 1) {
                $chk ^= $G[$i];
            }
        }
    }
    return $chk;
}

function tokenlock_segwit_decode($addr)
{
    $C = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
    if ($addr !== strtolower($addr) && $addr !== strtoupper($addr)) {
        return null;
    }
    $a = strtolower($addr);
    $pos = strrpos($a, '1');
    if ($pos === false || $pos < 1 || $pos + 7 > strlen($a) || strlen($a) > 90) {
        return null;
    }
    $hrp = substr($a, 0, $pos);
    $data = array();
    for ($i = $pos + 1; $i < strlen($a); $i++) {
        $v = strpos($C, $a[$i]);
        if ($v === false) {
            return null;
        }
        $data[] = $v;
    }
    $exp = array();
    for ($i = 0; $i < strlen($hrp); $i++) {
        $exp[] = ord($hrp[$i]) >> 5;
    }
    $exp[] = 0;
    for ($i = 0; $i < strlen($hrp); $i++) {
        $exp[] = ord($hrp[$i]) & 31;
    }
    $pm = tokenlock_bech32_polymod(array_merge($exp, $data));
    $version = $data[0];
    if (!($version === 0 ? $pm === 1 : $pm === 0x2bc830a3)) {
        return null;
    }
    $acc = 0;
    $bits = 0;
    $prog = '';
    foreach (array_slice($data, 1, -6) as $v) {
        $acc = (($acc << 5) | $v) & 0xffffff;
        $bits += 5;
        while ($bits >= 8) {
            $bits -= 8;
            $prog .= chr(($acc >> $bits) & 255);
        }
    }
    if ($bits >= 5 || (($acc << (8 - $bits)) & 255)) {
        return null;
    }
    if (strlen($prog) < 2 || strlen($prog) > 40 || $version > 16 || ($version === 0 && strlen($prog) !== 20 && strlen($prog) !== 32)) {
        return null;
    }
    return array('hrp' => $hrp, 'version' => $version, 'program' => $prog);
}

/** Decode an address: array(type, hash, script) or null. */
function tokenlock_decode_address($address)
{
    $a = trim((string) $address);
    if (preg_match('/^(bc|tb|bcrt)1/i', $a)) {
        $d = tokenlock_segwit_decode($a);
        if (!$d) {
            return null;
        }
        if ($d['version'] === 0 && strlen($d['program']) === 20) {
            return array('type' => 'p2wpkh', 'hash' => $d['program'], 'script' => "\x00\x14" . $d['program']);
        }
        if ($d['version'] === 1 && strlen($d['program']) === 32) {
            return array('type' => 'p2tr', 'hash' => $d['program'], 'script' => "\x51\x20" . $d['program']);
        }
        return null;
    }
    $b = tokenlock_b58check_decode($a);
    if ($b === null || strlen($b) !== 21) {
        return null;
    }
    $v = ord($b[0]);
    $h = substr($b, 1);
    if ($v === 0x00 || $v === 0x6f) {
        return array('type' => 'p2pkh', 'hash' => $h, 'script' => "\x76\xa9\x14" . $h . "\x88\xac");
    }
    if ($v === 0x05 || $v === 0xc4) {
        return array('type' => 'p2sh', 'hash' => $h, 'script' => "\xa9\x14" . $h . "\x87");
    }
    return null;
}

function tokenlock_legacy_message_hash($message)
{
    return tokenlock_dsha("\x18Bitcoin Signed Message:\n" . tokenlock_varint(strlen($message)) . $message);
}

function tokenlock_bip322_to_spend($message, $script)
{
    $mh = tokenlock_tagged_hash('BIP0322-signed-message', $message);
    $scriptSig = "\x00\x20" . $mh;
    $tx = pack('V', 0) . "\x01" . str_repeat("\x00", 32) . "\xff\xff\xff\xff" . tokenlock_varint(strlen($scriptSig)) . $scriptSig . pack('V', 0)
        . "\x01" . str_repeat("\x00", 8) . tokenlock_varint(strlen($script)) . $script . pack('V', 0);
    return tokenlock_dsha($tx);
}

function tokenlock_parse_witness($b)
{
    $i = 0;
    $L = strlen($b);
    $rd = function () use ($b, &$i, $L) {
        if ($i >= $L) {
            return null;
        }
        $f = ord($b[$i++]);
        if ($f < 0xfd) {
            return $f;
        }
        if ($f === 0xfd && $i + 2 <= $L) {
            $v = ord($b[$i]) | (ord($b[$i + 1]) << 8);
            $i += 2;
            return $v;
        }
        return null;
    };
    $n = $rd();
    if ($n === null || $n < 1 || $n > 10) {
        return null;
    }
    $items = array();
    for ($k = 0; $k < $n; $k++) {
        $len = $rd();
        if ($len === null || $i + $len > $L) {
            return null;
        }
        $items[] = substr($b, $i, $len);
        $i += $len;
    }
    return $i === $L ? $items : null;
}

/** Strict DER ECDSA signature → array(r, s) or null. */
function tokenlock_parse_der($d)
{
    $L = strlen($d);
    if ($L < 8 || $L > 72 || $d[0] !== "\x30" || ord($d[1]) !== $L - 2) {
        return null;
    }
    $i = 2;
    $out = array();
    for ($k = 0; $k < 2; $k++) {
        if ($i + 2 > $L || $d[$i] !== "\x02") {
            return null;
        }
        $len = ord($d[$i + 1]);
        $i += 2;
        if ($len < 1 || $len > 33 || $i + $len > $L) {
            return null;
        }
        $v = substr($d, $i, $len);
        if (ord($v[0]) & 0x80) {
            return null;
        }
        if ($len > 1 && $v[0] === "\x00" && !(ord($v[1]) & 0x80)) {
            return null;
        }
        $out[] = TokenlockSecp::int($v);
        $i += $len;
    }
    return $i === $L ? $out : null;
}

function tokenlock_verify_bip322($addr, $message, $sig)
{
    $w = tokenlock_parse_witness($sig);
    if (!$w) {
        return false;
    }
    $txid = tokenlock_bip322_to_spend($message, $addr['script']);
    $outpoint = $txid . pack('V', 0);
    $opret = str_repeat("\x00", 8) . "\x01\x6a";
    if ($addr['type'] === 'p2wpkh' || $addr['type'] === 'p2sh') {
        if (count($w) !== 2 || strlen($w[1]) !== 33) {
            return false;
        }
        $pub = $w[1];
        $pkh = tokenlock_hash160($pub);
        if ($addr['type'] === 'p2wpkh' && $pkh !== $addr['hash']) {
            return false;
        }
        if ($addr['type'] === 'p2sh' && tokenlock_hash160("\x00\x14" . $pkh) !== $addr['hash']) {
            return false;
        }
        if (substr($w[0], -1) !== "\x01") {
            return false; // hash type must be SIGHASH_ALL
        }
        $rs = tokenlock_parse_der(substr($w[0], 0, -1));
        $Q = TokenlockSecp::parsePub($pub);
        if (!$rs || !$Q) {
            return false;
        }
        // Low-S only (S <= n/2), like the hosted check.
        if (gmp_cmp($rs[1], gmp_div_q(TokenlockSecp::$n, 2)) > 0) {
            return false;
        }
        $scriptCode = "\x19\x76\xa9\x14" . $pkh . "\x88\xac";
        $pre = pack('V', 0) . tokenlock_dsha($outpoint) . tokenlock_dsha(pack('V', 0)) . $outpoint . $scriptCode . str_repeat("\x00", 8) . pack('V', 0) . tokenlock_dsha($opret) . pack('V', 0) . pack('V', 1);
        return TokenlockSecp::ecdsaVerify($rs[0], $rs[1], tokenlock_dsha($pre), $Q);
    }
    if ($addr['type'] === 'p2tr') {
        if (count($w) !== 1) {
            return false;
        }
        $s = $w[0];
        $ht = 0;
        $raw = $s;
        if (strlen($s) === 65) {
            $ht = ord($s[64]);
            $raw = substr($s, 0, 64);
            if ($ht !== 1) {
                return false;
            }
        } elseif (strlen($s) !== 64) {
            return false;
        }
        $script = $addr['script'];
        $msg = "\x00" . chr($ht) . pack('V', 0) . pack('V', 0) . hash('sha256', $outpoint, true) . hash('sha256', str_repeat("\x00", 8), true)
            . hash('sha256', tokenlock_varint(strlen($script)) . $script, true) . hash('sha256', pack('V', 0), true) . hash('sha256', $opret, true) . "\x00" . pack('V', 0);
        return TokenlockSecp::schnorrVerify($raw, tokenlock_tagged_hash('TapSighash', $msg), $addr['hash']);
    }
    return false;
}

function tokenlock_verify_legacy($addr, $message, $sig)
{
    if (strlen($sig) !== 65) {
        return false;
    }
    $h = ord($sig[0]);
    if ($h < 27 || $h > 42) {
        return false;
    }
    $Q = TokenlockSecp::recover(TokenlockSecp::int(substr($sig, 1, 32)), TokenlockSecp::int(substr($sig, 33, 32)), ($h - 27) & 3, tokenlock_legacy_message_hash($message));
    if ($Q === null) {
        return false;
    }
    $comp = TokenlockSecp::compressed($Q);
    switch ($addr['type']) {
        case 'p2pkh':
            return tokenlock_hash160($comp) === $addr['hash'] || tokenlock_hash160(TokenlockSecp::uncompressed($Q)) === $addr['hash'];
        case 'p2wpkh':
            return tokenlock_hash160($comp) === $addr['hash'];
        case 'p2sh':
            return tokenlock_hash160("\x00\x14" . tokenlock_hash160($comp)) === $addr['hash'];
        case 'p2tr':
            $q = TokenlockSecp::tweakTaproot(substr($comp, 1));
            return $q !== null && $q === $addr['hash'];
    }
    return false;
}

/** A little-endian byte reader that throws RuntimeException past the end. */
function tokenlock_reader($b)
{
    $st = new stdClass();
    $st->b = $b;
    $st->i = 0;
    $st->L = strlen($b);
    return $st;
}
function tokenlock_rd_take($st, $n)
{
    if ($n < 0 || $st->i + $n > $st->L) {
        throw new RuntimeException('short');
    }
    $x = substr($st->b, $st->i, $n);
    $st->i += $n;
    return $x;
}
function tokenlock_rd_vi($st)
{
    $f = ord(tokenlock_rd_take($st, 1));
    if ($f < 0xfd) {
        return $f;
    }
    if ($f === 0xfd) {
        $x = unpack('v', tokenlock_rd_take($st, 2));
        return $x[1];
    }
    if ($f === 0xfe) {
        $x = unpack('V', tokenlock_rd_take($st, 4));
        return $x[1];
    }
    throw new RuntimeException('varint');
}
function tokenlock_rd_u32($st)
{
    $x = unpack('V', tokenlock_rd_take($st, 4));
    return $x[1];
}

/**
 * Structure of a BIP-322 full signature, independent of the message: nVersion 0 + segwit marker, one input at index 0
 * with sequence 0, one OP_RETURN output of 0, locktime 0, nothing after it. false = not "nVersion 0 + marker" (treat as
 * simple: a simple witness starts with its item count, never 0); null = such a transaction but not the to_sign shape;
 * else array('txid' => …, 'scriptSig' => …, 'items' => array(…)).
 */
function tokenlock_bip322_parse_full($b)
{
    if (strlen($b) < 10 || substr($b, 0, 4) !== "\x00\x00\x00\x00" || $b[4] !== "\x00" || $b[5] !== "\x01") {
        return false;
    }
    try {
        $r = tokenlock_reader($b);
        tokenlock_rd_take($r, 6);
        if (tokenlock_rd_vi($r) !== 1) {
            return null;
        }
        $txid = tokenlock_rd_take($r, 32);
        $vout = tokenlock_rd_u32($r);
        $scriptSig = tokenlock_rd_take($r, tokenlock_rd_vi($r));
        $seq = tokenlock_rd_u32($r);
        if (tokenlock_rd_vi($r) !== 1) {
            return null;
        }
        $value = tokenlock_rd_take($r, 8);
        $outScript = tokenlock_rd_take($r, tokenlock_rd_vi($r));
        $n = tokenlock_rd_vi($r);
        if ($n < 1 || $n > 16) {
            return null;
        }
        $items = array();
        for ($k = 0; $k < $n; $k++) {
            $items[] = tokenlock_rd_take($r, tokenlock_rd_vi($r));
        }
        $lock = tokenlock_rd_u32($r);
        if ($r->i !== $r->L || $lock !== 0 || $seq !== 0 || $vout !== 0) {
            return null;
        }
        if ($value !== str_repeat("\x00", 8) || $outScript !== "\x6a") {
            return null;
        }
        return array('txid' => $txid, 'scriptSig' => $scriptSig, 'items' => $items);
    } catch (Throwable $e) {
        return null;
    }
}

/** The scriptSig a to_sign input carries: empty, or (P2SH-P2WPKH) one push of 0014<hash160(key)> hashing to the address. */
function tokenlock_bip322_scriptsig_ok($addr, $ss)
{
    if ($addr['type'] !== 'p2sh') {
        return $ss === '';
    }
    return strlen($ss) === 23 && substr($ss, 0, 3) === "\x16\x00\x14" && tokenlock_hash160(substr($ss, 1)) === $addr['hash'];
}

function tokenlock_encode_witness($items)
{
    $out = tokenlock_varint(count($items));
    foreach ($items as $x) {
        $out .= tokenlock_varint(strlen($x)) . $x;
    }
    return $out;
}

/**
 * If $b is a BIP-322 full signature, check it is the to_sign transaction for ($addr, $message) and return its witness
 * re-encoded as a simple signature. false = not a full signature (try it as simple); null = one that does not match.
 */
function tokenlock_bip322_full_to_simple($addr, $message, $b)
{
    $f = tokenlock_bip322_parse_full($b);
    if ($f === false) {
        return false;
    }
    if ($f === null || $addr['type'] === 'p2pkh' || !tokenlock_bip322_scriptsig_ok($addr, $f['scriptSig']) || $f['txid'] !== tokenlock_bip322_to_spend($message, $addr['script'])) {
        return null;
    }
    return tokenlock_encode_witness($f['items']);
}

/** Witness stack items (1-16) of a simple signature, or null. */
function tokenlock_witness_items($b)
{
    try {
        $r = tokenlock_reader($b);
        $n = tokenlock_rd_vi($r);
        if ($n < 1 || $n > 16) {
            return null;
        }
        $items = array();
        for ($k = 0; $k < $n; $k++) {
            $items[] = tokenlock_rd_take($r, tokenlock_rd_vi($r));
        }
        return $r->i === $r->L ? $items : null;
    } catch (Throwable $e) {
        return null;
    }
}

/** The witness shapes every TOKENLOCK verifier accepts (same rule as the hosted check). */
function tokenlock_witness_shape_ok($type, $items)
{
    if (!$items) {
        return false;
    }
    if ($type === 'p2wpkh' || $type === 'p2sh') {
        if (count($items) !== 2 || strlen($items[1]) !== 33 || strlen($items[0]) < 9 || substr($items[0], -1) !== "\x01") {
            return false;
        }
        $rs = tokenlock_parse_der(substr($items[0], 0, -1));
        TokenlockSecp::init();
        $n = TokenlockSecp::$n;
        return $rs !== null && gmp_cmp($rs[0], 0) > 0 && gmp_cmp($rs[0], $n) < 0 && gmp_cmp($rs[1], 0) > 0 && gmp_cmp($rs[1], gmp_div_q($n, 2)) <= 0;
    }
    if ($type === 'p2tr') {
        return count($items) === 1 && (strlen($items[0]) === 64 || (strlen($items[0]) === 65 && $items[0][64] === "\x01"));
    }
    return false;
}

/** Why a signature cannot be checked as written (the same codes and texts as the hosted check). */
function tokenlock_format_problems()
{
    return array(
        'address_format' => 'The address is not a supported Bitcoin address as written (exact text, lower-case bech32, at most 100 characters).',
        'encoding' => 'The signature is not base64 or hex.',
        'base64_variant' => 'The signature uses a base64 variant we do not accept (URL-safe characters, missing = padding, or non-ASCII spaces). Send standard padded base64.',
        'bip137_header' => 'The legacy signature has a header byte outside 27-42.',
        'legacy_length' => 'A signature for a 1... address must be a 65-byte legacy (BIP-137) signature; BIP-322 is not supported for these addresses.',
        'bip322_full_template' => 'The BIP-322 full signature is not the standard to_sign transaction for this address.',
        'bip322_witness_shape' => 'The BIP-322 signature is not a supported single-key witness (strict DER, low-S, SIGHASH_ALL; Taproot key-path only).',
    );
}

function tokenlock_sig_bytes_problem($addr, $b)
{
    if (strlen($b) === 65) {
        $h = ord($b[0]);
        return $h >= 27 && $h <= 42 ? null : 'bip137_header';
    }
    if ($addr['type'] === 'p2pkh') {
        return 'legacy_length';
    }
    $f = tokenlock_bip322_parse_full($b);
    // Shape only: a P2SH-P2WPKH redeem push for the wrong key is a wrong key, not a format problem.
    $shapeOk = is_array($f) && ($addr['type'] !== 'p2sh' ? $f['scriptSig'] === '' : strlen($f['scriptSig']) === 23 && substr($f['scriptSig'], 0, 3) === "\x16\x00\x14");
    if ($f === null || (is_array($f) && !$shapeOk)) {
        return 'bip322_full_template';
    }
    return tokenlock_witness_shape_ok($addr['type'], is_array($f) ? $f['items'] : tokenlock_witness_items($b)) ? null : 'bip322_witness_shape';
}

/**
 * Why $signature (for $address) cannot be checked at all, independent of the message: a key of
 * tokenlock_format_problems(), or null when it is well formed (then a failure means the wrong key or message).
 */
function tokenlock_signature_format_problem($address, $signature)
{
    try {
        if (!is_string($address) || strlen($address) > 100 || $address !== trim($address)
            || (preg_match('/^(bc|tb|bcrt)1/i', $address) && $address !== strtolower($address))) {
            return 'address_format';
        }
        $addr = tokenlock_decode_address($address);
        if (!$addr) {
            return 'address_format';
        }
        if (!is_string($signature) || strlen($signature) > 4096 * 4) {
            return 'encoding';
        }
        if (function_exists('mb_strlen') && @mb_strlen($signature, 'UTF-8') > 4096) {
            return 'encoding';
        }
        $s = preg_replace('/[ \t\r\n\f\x0B]+/', '', $signature);
        $h = preg_replace('/^0x/i', '', $s);
        $isHex = $h !== '' && preg_match('/^[0-9a-fA-F]+$/', $h) && strlen($h) % 2 === 0;
        $isB64 = $s !== '' && strlen($s) % 4 === 0 && preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $s);
        if ($isHex) {
            $hp = tokenlock_sig_bytes_problem($addr, hex2bin($h));
            if ($hp === null || !$isB64) {
                return $hp;
            }
            return tokenlock_sig_bytes_problem($addr, base64_decode($s, true)) !== null ? $hp : null;
        }
        if ($isB64) {
            return tokenlock_sig_bytes_problem($addr, base64_decode($s, true));
        }
        // Not clean: would a lenient decoder have read it as a well-formed signature? Then name the variant.
        // Unicode whitespace a lenient decoder might skip (explicit, so every implementation agrees).
        $loose = preg_replace('/[\x{0009}-\x{000D}\x{0020}\x{0085}\x{00A0}\x{1680}\x{180E}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}]+/u', '', $signature);
        if ($loose === null) {
            $loose = preg_replace('/[ \t\r\n\f\x0B]+/', '', $signature);
        }
        $loose = rtrim(strtr($loose, '-_', '+/'), '=');
        if ($loose !== '' && preg_match('/^[A-Za-z0-9+\/]+$/', $loose) && strlen($loose) % 4 !== 1) {
            $b = base64_decode($loose . str_repeat('=', (4 - strlen($loose) % 4) % 4), true);
            if ($b !== false && $b !== '' && tokenlock_sig_bytes_problem($addr, $b) === null) {
                return 'base64_variant';
            }
        }
        return 'encoding';
    } catch (Throwable $e) {
        return 'encoding';
    }
}

/** The exact message first, then only its LF<->CRLF equivalent (when different). Never trimmed or otherwise normalized. */
function tokenlock_message_candidates($message)
{
    $out = array($message);
    $lf = str_replace("\r\n", "\n", $message);
    if ($lf !== $message) {
        $out[] = $lf;
    }
    $crlf = str_replace("\n", "\r\n", $lf);
    if ($crlf !== $message) {
        $out[] = $crlf;
    }
    return $out;
}

/** Signature bytes to try: strict base64 (standard alphabet, padded), then even-length hex with an optional 0x. */
function tokenlock_signature_candidates($signature)
{
    $s = preg_replace('/[ \t\r\n\f\x0B]+/', '', $signature);
    $out = array();
    if ($s !== '' && strlen($s) % 4 === 0 && preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $s)) {
        $b = base64_decode($s, true);
        if ($b !== false && $b !== '') {
            $out[] = $b;
        }
    }
    $h = preg_replace('/^0x/i', '', $s);
    if ($h !== '' && strlen($h) % 2 === 0 && preg_match('/^[0-9a-fA-F]+$/', $h)) {
        $out[] = hex2bin($h);
    }
    return $out;
}

function tokenlock_verify_signature_bytes($addr, $message, $sig)
{
    if (strlen($sig) === 65) {
        $h = ord($sig[0]);
        return $h >= 27 && $h <= 42 && tokenlock_verify_legacy($addr, $message, $sig);
    }
    if ($addr['type'] === 'p2pkh') {
        return false; // BIP-322 for 1… addresses is not supported
    }
    $simple = tokenlock_bip322_full_to_simple($addr, $message, $sig);
    if ($simple === null) {
        return false;
    }
    return tokenlock_verify_bip322($addr, $message, $simple === false ? $sig : $simple);
}

/**
 * Does $signature prove $address signed exactly $message (or its LF<->CRLF equivalent)? $signature is base64, or hex
 * (optional 0x) as a fallback; whitespace inside it is ignored. Never throws (except without GMP).
 */
function tokenlock_verify_message_signature($address, $message, $signature)
{
    TokenlockSecp::init();
    if (!is_string($address) || !is_string($message) || !is_string($signature)) {
        return false;
    }
    // Signatures over 4096 characters are refused without decoding (real ones are under 1,000).
    if (strlen($signature) > 4096 && (!function_exists('mb_strlen') || mb_strlen($signature, 'UTF-8') > 4096)) {
        return false;
    }
    // Same address strictness as the hosted check: at most 100 characters, no surrounding whitespace, lower-case bech32.
    if (strlen($address) > 100 || $address !== trim($address) || (preg_match('/^(bc|tb|bcrt)1/i', $address) && $address !== strtolower($address))) {
        return false;
    }
    $addr = tokenlock_decode_address($address);
    if (!$addr) {
        return false;
    }
    try {
        $sigs = tokenlock_signature_candidates($signature);
        foreach (tokenlock_message_candidates($message) as $m) {
            foreach ($sigs as $sig) {
                if (tokenlock_verify_signature_bytes($addr, $m, $sig)) {
                    return true;
                }
            }
        }
        return false;
    } catch (Throwable $e) {
        return false;
    }
}
