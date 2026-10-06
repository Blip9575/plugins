<?php

/*
 * Copyright (C) 2026 os-amneziawg contributors
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\AmneziaWG;

/**
 * Random AmneziaWG 2.0 obfuscation parameters, within the recommendations of awg(8):
 *   Jc 3-10, Jmin about 8 (below Jmax), Jmax about 80, S1/S2/S3 15-150, S4 15-32,
 *   H1-H4 numbers or ranges from 5 to 4294967295 that do not overlap.
 * S1, S2 and S3 differ from each other and S1 + 56 is not S2 (a known rule of earlier AmneziaWG versions).
 *
 * Without a protocol the signature packets I1-I5 are empty, a profile without them works on its own. With a protocol
 * I1 is a packet that imitates the start of a session of that UDP protocol and I2-I5 are empty. The Amnezia
 * documentation only describes the syntax, it names QUIC, DNS and SIP and suggests capturing a real packet. The packets
 * here are built from the protocol specifications, the parts that change from packet to packet are random tags:
 * they have the layout of the protocol, they are not real sessions. The QUIC and HTTP/3 packets are real QUIC version 1
 * Initial packets (RFC 9000, 9001) with a TLS 1.3 ClientHello inside, encrypted with the standard Initial keys, so
 * a device that decrypts them sees a valid ClientHello. The packet is built once when the profile is generated and
 * stays the same in every emission, because a signature packet can only hold fixed bytes and random tags, and the
 * encrypted part can not be random. The <c> tag is not used, amneziawg-go does not implement it.
 */
class ParamGenerator
{
    /* header ranges are picked from this span, small values are left to standard WireGuard message types */
    private const H_LOW = 100000;
    private const H_HIGH = 4294967295;

    /* imitated protocols with their usual UDP port, the dropdown of the instance dialog lists them as "DNS (53)" */
    public const PROTOCOLS = [
        'http3' => ['label' => 'HTTP/3', 'port' => '443'],
        'dns' => ['label' => 'DNS', 'port' => '53'],
        'ntp' => ['label' => 'NTP', 'port' => '123'],
        'stun' => ['label' => 'STUN', 'port' => '3478'],
        'sip' => ['label' => 'SIP', 'port' => '5060'],
    ];

    /* protocols whose signature packets are QUIC Initial packets */
    public const INITIAL = ['http3'];

    /**
     * Server names for the TLS ClientHello inside the QUIC Initial packets, one is picked at random for each profile.
     * This list is a choice of this plugin, no official source gives one: large, widely used hosts that mobile devices
     * and laptops contact over HTTP/3 all day.
     */
    public const SNI = [
        'www.google.com', 'www.youtube.com', 'fonts.gstatic.com', 'www.gstatic.com', 'i.ytimg.com',
        'www.cloudflare.com', 'cdnjs.cloudflare.com', 'www.facebook.com', 'static.xx.fbcdn.net',
        'www.instagram.com', 'www.microsoft.com', 'update.googleapis.com', 'www.apple.com', 'images.apple.com',
        'www.netflix.com',
    ];

    /**
     * @param string $sni server name for the HTTP/3 signature packets, a random one of SNI when not given
     */
    public static function awg2(string $protocol = '', ?string $sni = null, string $template = '')
    {
        if (in_array($protocol, self::INITIAL, true)) {
            /* a QUIC client sends nothing between its Initial packets and the server's answer: no junk packets, and
             * the handshake initiation (148 + S1) and the response (92 + S2) get the size of an Initial (1200-1232) */
            $result = ['jc' => '0', 'jmin' => '', 'jmax' => ''];
            $result += self::prefixes(true);
        } else {
            $result = [
                'jc' => (string)random_int(3, 10),
                'jmin' => (string)random_int(6, 10),
                'jmax' => (string)random_int(60, 100),
            ];
            $result += self::prefixes();
        }

        /* one range in each quarter of the span, handed out in random order, so they can not overlap */
        $quarter = intdiv(self::H_HIGH - self::H_LOW, 4);
        $slots = [0, 1, 2, 3];
        for ($i = 3; $i > 0; $i--) {
            $j = random_int(0, $i);
            [$slots[$i], $slots[$j]] = [$slots[$j], $slots[$i]];
        }
        foreach ($slots as $idx => $slot) {
            $low = self::H_LOW + $slot * $quarter;
            $width = random_int(10000, 1000000);
            $start = random_int($low, $low + $quarter - $width - 1);
            $result['h' . ($idx + 1)] = $start . '-' . ($start + $width);
        }

        foreach (['i1', 'i2', 'i3', 'i4', 'i5'] as $field) {
            $result[$field] = '';
        }
        if (isset(self::PROTOCOLS[$protocol])) {
            /* one signature packet per datagram: I1, and I2 when the protocol opens with two packets; HTTP/3
             * use the captured Initial packets of a real client instead of the built-in ClientHello when given */
            $packets = in_array($protocol, self::INITIAL, true) && trim($template) !== '' ?
                array_map(fn($packet) => self::bytes($packet), self::templateInitials($template, $sni)) :
                (array)self::$protocol($sni);
            foreach (array_values($packets) as $idx => $packet) {
                $result['i' . ($idx + 1)] = $packet;
            }
        }

        return $result;
    }

    /**
     * Random prefix sizes S1-S4 (awg(8): S1/S2/S3 15-150 and S4 15-32), S1, S2 and S3 differ from each other and
     * S1 + 56 is not S2. Header protection needs S1-S4 of at least 12, these are always above that. With $initial
     * the handshake packets get the size of a QUIC Initial: S1 1052-1084 and S2 1108-1140 (kernel limits 1304, 1360).
     */
    public static function prefixes(bool $initial = false)
    {
        do {
            $s = $initial ? [random_int(1052, 1084), random_int(1108, 1140), random_int(15, 150)] :
                [random_int(15, 150), random_int(15, 150), random_int(15, 150)];
            $ok = count(array_unique($s)) === 3 && $s[0] + 56 !== $s[1];
        } while (!$ok);

        return [
            's1' => (string)$s[0],
            's2' => (string)$s[1],
            's3' => (string)$s[2],
            's4' => (string)random_int(15, 32),
        ];
    }

    /**
     * AmneziaWG 3.x profile: a new header protection key, 32 random bytes in the format of a WireGuard key (clamped
     * like wg genkey does). The prefixes are only included when the caller found S1-S4 empty or below 12. Padding, the
     * timers, RandomTrailers and DisableCookies are left alone, the documentation has no recommended values for them.
     */
    public static function awg3(bool $withPrefixes = false)
    {
        $key = random_bytes(32);
        $key[0] = chr(ord($key[0]) & 248);
        $key[31] = chr((ord($key[31]) & 127) | 64);
        $result = ['headerprotectionkey' => base64_encode($key)];

        return $withPrefixes ? $result + self::prefixes() : $result;
    }

    /**
     * Everything the gear of the instance dialog sets for a profile: the AmneziaWG 2.0 parameters, the listen port of
     * the protocol and an MTU, and with AmneziaWG 3.x a new header protection key and the 3.x values of the profile.
     * MTU: 1280 for HTTP/3 (QUIC sized packets), otherwise the value the kernel picks for this S4.
     * 3.x: the signature packets are sent before every handshake, a longer rekey interval sends them less often in the
     * middle of a flow. Measured: the timers are seconds, and they must be the same on both ends or the server rekeys
     * first and sends its own I1 (the peer generator copies them into the peer configuration). HTTP/3 adds
     * a padding of 0-32 bytes to every packet; RandomTrailers stays off, the documentation recommends equal S1-S4
     * with it.
     * None of these values comes from the documentation, they are this plugin's choice.
     */
    public static function profile(string $protocol, ?string $sni = null, bool $awg3 = false, string $template = '')
    {
        $result = self::awg2($protocol, $sni, $template);
        if (isset(self::PROTOCOLS[$protocol])) {
            $result['port'] = self::PROTOCOLS[$protocol]['port'];
        }
        $result['mtu'] = in_array($protocol, self::INITIAL, true) ?
            '1280' : (string)self::kernelMtu((int)$result['s4']);
        return $awg3 ? $result + self::awg3() + self::awg3Values($protocol) : $result;
    }

    /** the AmneziaWG 3.x values of a profile besides the key, see profile() */
    public static function awg3Values(string $protocol)
    {
        return [
            'rekeyaftertime' => '300',
            'rejectaftertime' => '420',
            'contentpaddingaddition' => in_array($protocol, self::INITIAL, true) ? '0-32' : '',
            'randomtrailers' => '0',
        ];
    }

    /**
     * The MTU amnezia-kmod 3.1.0 gives an interface without a fixed MTU, measured on a 1500 byte path: 1420 when S4 is
     * at most 12, then 16 bytes less for every 16 bytes of S4 (see the notes of this plugin, header size)
     */
    public static function kernelMtu(int $s4)
    {
        return $s4 <= 12 ? 1420 : 1408 - 16 * intdiv($s4 - 13, 16);
    }

    /** static bytes tag */
    private static function bytes(string $data)
    {
        return '<b 0x' . bin2hex($data) . '>';
    }

    /** random tags, a tag is limited to 1000 */
    private static function random(int $length, string $tag = 'r')
    {
        $result = '';
        while ($length > 0) {
            $chunk = min($length, 1000);
            $result .= "<{$tag} {$chunk}>";
            $length -= $chunk;
        }
        return $result;
    }

    /** text with random parts: strings are static, [n] is n random letters */
    private static function text(array $parts)
    {
        $result = '';
        $static = '';
        foreach ($parts as $part) {
            if (is_array($part)) {
                $result .= ($static !== '' ? self::bytes($static) : '') . self::random($part[0], 'rc');
                $static = '';
            } else {
                $static .= $part;
            }
        }
        return $result . ($static !== '' ? self::bytes($static) : '');
    }

    /** DNS query (RFC 1035) for a random name, with an EDNS0 OPT record like current resolvers send */
    private static function dns()
    {
        $tlds = ['com', 'net', 'org', 'io', 'info'];
        $types = [1, 28, 65]; /* A, AAAA, HTTPS */
        $labels = random_int(1, 2);
        $result = self::random(2) . self::bytes("\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01");
        for ($i = 0; $i < $labels; $i++) {
            $length = random_int(6, 14);
            $result .= self::bytes(chr($length)) . self::random($length, 'rc');
        }
        $tld = $tlds[random_int(0, count($tlds) - 1)];
        return $result . self::bytes(
            chr(strlen($tld)) . $tld . "\x00" . pack('n', $types[random_int(0, 2)]) . "\x00\x01" .
            "\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00"
        );
    }

    /**
     * HTTP/3 client, the way a current browser opens a connection: empty source connection id, ALPN h3 and the hybrid
     * post-quantum key share X25519MLKEM768. That ClientHello is about 1.5 kB and does not fit in one datagram, so it
     * is sent in two Initial packets, I1 and I2 (the keys and the connection id are those of a real connection start).
     */
    private static function http3(?string $sni = null)
    {
        return array_map(fn($packet) => self::bytes($packet), self::quicInitials(0, true, $sni));
    }

    /** QUIC variable length integer (RFC 9000 section 16) */
    private static function varint(int $value)
    {
        if ($value < 0x40) {
            return chr($value);
        } elseif ($value < 0x4000) {
            return pack('n', 0x4000 | $value);
        }
        return pack('N', 0x80000000 | $value);
    }

    /** HKDF-Expand-Label of TLS 1.3 with SHA-256 and an empty context, the output is at most one hash block */
    private static function expandLabel(string $secret, string $label, int $length)
    {
        $label = 'tls13 ' . $label;
        $info = pack('n', $length) . chr(strlen($label)) . $label . "\x00";
        return substr(hash_hmac('sha256', $info . "\x01", $secret, true), 0, $length);
    }

    /** TLS extension */
    private static function extension(int $type, string $data)
    {
        return pack('nn', $type, strlen($data)) . $data;
    }

    /**
     * TLS 1.3 ClientHello for QUIC (RFC 8446, 9001): empty session id, TLS_AES_128_GCM_SHA256 and the other two
     * TLS 1.3 suites, x25519 key share, ALPN h3 and the QUIC transport parameters. Browsers shuffle the extension
     * order, so does this.
     */
    private static function clientHello(string $sni, string $scid, bool $hybrid)
    {
        /* X25519MLKEM768 (0x11ec): an ML-KEM-768 encapsulation key of 1184 bytes and an x25519 key of 32 bytes, the
         * bytes are random, nobody can tell them from a key without the private part */
        $groups = $hybrid ? [0x11ec, 0x001d, 0x0017, 0x0018] : [0x001d, 0x0017, 0x0018];
        $shares = ($hybrid ? pack('nn', 0x11ec, 1216) . random_bytes(1216) : '') . pack('nn', 0x001d, 32) . random_bytes(32);
        $sigalgs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];
        $params = '';
        foreach (
            [0x01 => self::varint(30000), 0x03 => self::varint(1472), 0x04 => self::varint(15728640),
             0x05 => self::varint(6291456), 0x06 => self::varint(6291456), 0x07 => self::varint(6291456),
             0x08 => self::varint(100), 0x09 => self::varint(100), 0x0e => self::varint(4), 0x0f => $scid,
             27 + 31 * random_int(1, 100) => random_bytes(random_int(1, 16))] as $id => $value
        ) {
            $params .= self::varint($id) . self::varint(strlen($value)) . $value;
        }
        $extensions = [
            self::extension(0, pack('n', strlen($sni) + 3) . "\x00" . pack('n', strlen($sni)) . $sni),
            self::extension(10, pack('n', 2 * count($groups)) . pack('n*', ...$groups)),
            self::extension(13, pack('n', 2 * count($sigalgs)) . pack('n*', ...$sigalgs)),
            self::extension(16, pack('n', 3) . "\x02h3"),
            self::extension(43, "\x02\x03\x04"),
            self::extension(45, "\x01\x01"),
            self::extension(51, pack('n', strlen($shares)) . $shares),
            self::extension(57, $params),
        ];
        for ($i = count($extensions) - 1; $i > 0; $i--) {
            $j = random_int(0, $i);
            [$extensions[$i], $extensions[$j]] = [$extensions[$j], $extensions[$i]];
        }
        $extensions = implode('', $extensions);
        $body = "\x03\x03" . random_bytes(32) . "\x00" . pack('n', 6) . "\x13\x01\x13\x02\x13\x03" . "\x01\x00" .
            pack('n', strlen($extensions)) . $extensions;
        return "\x01" . substr(pack('N', strlen($body)), 1) . $body;
    }

    /**
     * QUIC version 1 client Initial packets of 1200-1232 bytes each (RFC 9000 section 17.2.2, RFC 9001 section 5): 8
     * byte destination connection id, no token, CRYPTO frames with the ClientHello of a random server name, padded with
     * PADDING frames, protected with the Initial secret that is derived from the destination connection id. A
     * ClientHello that does not fit in the first packet continues at its offset in a second packet (packet number 1).
     */
    private static function quicInitials(int $scidLength, bool $hybrid, ?string $sni = null)
    {
        $dcid = random_bytes(8);
        $scid = $scidLength > 0 ? random_bytes($scidLength) : '';
        $hello = self::clientHello($sni ?? self::SNI[random_int(0, count(self::SNI) - 1)], $scid, $hybrid);

        [$key, $iv, $hp] = self::initialKeys($dcid);

        $pnLength = 2;
        $head = "\x00\x00\x00\x01" . chr(8) . $dcid . chr($scidLength) . $scid . "\x00";
        $overhead = 1 + strlen($head) + 2 + $pnLength + 16; /* first byte, header, length, packet number, tag */

        $packets = [];
        $offset = 0;
        for ($pn = 0; $offset < strlen($hello) || $pn === 0; $pn++) {
            $payloadLength = random_int(1200, 1232) - $overhead;
            /* a CRYPTO frame is type, offset, length (two bytes) and the data */
            $room = $payloadLength - 2 - strlen(self::varint($offset)) - 1;
            $chunk = substr($hello, $offset, $room);
            $payload = "\x06" . self::varint($offset) . self::varint(strlen($chunk)) . $chunk;
            $payload .= str_repeat("\x00", $payloadLength - strlen($payload));
            $offset += strlen($chunk);

            $header = chr(0xC0 | ($pnLength - 1)) . $head . pack('n', 0x4000 | ($pnLength + $payloadLength + 16));
            $pnOffset = strlen($header);
            $header .= pack('n', $pn);
            $nonce = substr($iv, 0, 10) . (substr($iv, 10) ^ pack('n', $pn));
            $tag = '';
            $encrypted = openssl_encrypt($payload, 'aes-128-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $header, 16);
            $packet = $header . $encrypted . $tag;

            /* header protection, the sample starts 4 bytes after the start of the packet number */
            $mask = self::hpMask($hp, $packet, $pnOffset);
            $packet[0] = chr(ord($packet[0]) ^ (ord($mask[0]) & 0x0f));
            for ($i = 0; $i < $pnLength; $i++) {
                $packet[$pnOffset + $i] = chr(ord($packet[$pnOffset + $i]) ^ ord($mask[1 + $i]));
            }
            $packets[] = $packet;
        }
        return $packets;
    }

    /** client Initial keys of a destination connection id (RFC 9001 section 5.2): packet key, IV, header key */
    private static function initialKeys(string $dcid)
    {
        $secret = hash_hmac('sha256', $dcid, hex2bin('38762cf7f55934b34d179ae6a4c80cadccbb7f0a'), true);
        $secret = self::expandLabel($secret, 'client in', 32);
        return [
            self::expandLabel($secret, 'quic key', 16),
            self::expandLabel($secret, 'quic iv', 12),
            self::expandLabel($secret, 'quic hp', 16),
        ];
    }

    /** header protection mask (RFC 9001 section 5.4.3), the sample starts 4 bytes after the packet number */
    private static function hpMask(string $hp, string $packet, int $pnOffset)
    {
        return substr(openssl_encrypt(
            substr($packet, $pnOffset + 4, 16),
            'aes-128-ecb',
            $hp,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING
        ), 0, 5);
    }

    /** read a QUIC variable length integer at $pos and move $pos behind it */
    private static function readVarint(string $data, int &$pos)
    {
        if ($pos >= strlen($data)) {
            throw new \RuntimeException(gettext('The template ends in the middle of a packet.'));
        }
        $length = 1 << (ord($data[$pos]) >> 6);
        $value = ord($data[$pos]) & 0x3f;
        for ($i = 1; $i < $length; $i++) {
            $value = ($value << 8) | ord($data[$pos + $i] ?? "\x00");
        }
        $pos += $length;
        return $value;
    }

    /** random bytes, empty for a length of 0 (random_bytes() refuses it) */
    private static function randomBytes(int $length)
    {
        return $length > 0 ? random_bytes($length) : '';
    }

    /** GREASE value of TLS (RFC 8701): 0x0a0a, 0x1a1a, ... 0xfafa */
    private static function isGrease(int $value)
    {
        return ($value & 0x0f0f) === 0x0a0a && ($value >> 12) === (($value >> 4) & 0x0f);
    }

    /**
     * Signature packets from a template: the client Initial packets a real browser sent at the start of a QUIC
     * connection, pasted as hex (the UDP payload of each datagram, one per line, as Wireshark copies it). They are
     * decrypted with the Initial keys of their connection id, the ClientHello is put together from its CRYPTO frames
     * and gets the server name, a new random, session id, key shares, ECH GREASE bytes and connection ids; the
     * extension order is shuffled when the template has GREASE (Chromium does that on every connection). The frames
     * keep their layout (order, PING and PADDING, the way Chrome scatters the ClientHello), every datagram keeps its
     * size, and the packets are encrypted again with the keys of a new connection id. So the fingerprint of the
     * ClientHello is the one of that browser.
     * @throws \RuntimeException with a message for the dialog when the template can not be used
     */
    private static function templateInitials(string $template, ?string $sni = null)
    {
        $sni = $sni ?? self::SNI[random_int(0, count(self::SNI) - 1)];
        $datagrams = [];
        foreach (preg_split('/[\s,;]+/', trim($template)) as $chunk) {
            $chunk = preg_replace('/^0x/i', '', $chunk);
            if ($chunk === '') {
                continue;
            }
            if (!ctype_xdigit($chunk) || strlen($chunk) % 2 !== 0) {
                throw new \RuntimeException(gettext('The template must be hex, one datagram per line.'));
            }
            $datagrams[] = hex2bin($chunk);
        }
        if (count($datagrams) < 1 || count($datagrams) > 5) {
            throw new \RuntimeException(gettext('The template must hold one to five datagrams.'));
        }

        /* decrypt every packet and keep its layout */
        $packets = [];
        $stream = [];
        $dcid = null;
        foreach ($datagrams as $datagram) {
            if (strlen($datagram) < 1200) {
                /* RFC 9000 section 14.1: a client pads every datagram with an Initial packet to at least 1200 bytes */
                throw new \RuntimeException(
                    gettext('Every datagram must be at least 1200 bytes, copy the whole UDP payload.')
                );
            }
            $b0 = ord($datagram[0]);
            if (($b0 & 0xf0) !== 0xc0 || substr($datagram, 1, 4) !== "\x00\x00\x00\x01") {
                throw new \RuntimeException(gettext('Every datagram must start with a QUIC version 1 Initial packet.'));
            }
            $pos = 5;
            $id = substr($datagram, $pos + 1, ord($datagram[$pos]));
            $pos += 1 + strlen($id);
            $scid = substr($datagram, $pos + 1, ord($datagram[$pos]));
            $pos += 1 + strlen($scid);
            if (self::readVarint($datagram, $pos) !== 0) {
                throw new \RuntimeException(
                    gettext('The template has a token, capture the first connection to a new server.')
                );
            }
            $lengthOffset = $pos;
            $length = self::readVarint($datagram, $pos);
            $pnOffset = $pos;
            if ($dcid !== null && $id !== $dcid) {
                throw new \RuntimeException(gettext('The datagrams belong to different connections.'));
            }
            $dcid = $id;
            [$key, $iv, $hp] = self::initialKeys($dcid);
            if ($pnOffset + $length > strlen($datagram) || $length < 20) {
                throw new \RuntimeException(gettext('A packet is longer than its datagram.'));
            }
            $mask = self::hpMask($hp, $datagram, $pnOffset);
            $first = chr($b0 ^ (ord($mask[0]) & 0x0f));
            $pnLength = (ord($first) & 0x03) + 1;
            $pnBytes = substr($datagram, $pnOffset, $pnLength) ^ substr($mask, 1, $pnLength);
            $pn = (int)hexdec(bin2hex($pnBytes));
            $header = $first . substr($datagram, 1, $pnOffset - 1) . $pnBytes;
            $nonce = substr($iv, 0, 12 - 8) . (substr($iv, 4) ^ pack('J', $pn));
            $sealed = substr($datagram, $pnOffset + $pnLength, $length - $pnLength);
            $plain = openssl_decrypt(
                substr($sealed, 0, -16),
                'aes-128-gcm',
                $key,
                OPENSSL_RAW_DATA,
                $nonce,
                substr($sealed, -16),
                $header
            );
            if ($plain === false) {
                throw new \RuntimeException(
                    gettext('A packet does not decrypt as a client Initial, copy the first packets of a connection.')
                );
            }
            $trailer = substr($datagram, $pnOffset + $length);
            if (trim($trailer, "\x00") !== '') {
                throw new \RuntimeException(gettext('A datagram holds more than one packet, this is not supported.'));
            }
            $frames = [];
            for ($i = 0; $i < strlen($plain);) {
                $type = ord($plain[$i]);
                if ($type === 0x00) {
                    $run = strspn($plain, "\x00", $i);
                    $frames[] = ['pad', $run];
                    $i += $run;
                } elseif ($type === 0x01) {
                    $frames[] = ['ping'];
                    $i++;
                } elseif ($type === 0x06) {
                    $i++;
                    $offset = self::readVarint($plain, $i);
                    $size = self::readVarint($plain, $i);
                    $stream[$offset] = substr($plain, $i, $size);
                    $frames[] = ['crypto', $offset, $size];
                    $i += $size;
                } else {
                    throw new \RuntimeException(
                        sprintf(gettext('Unexpected frame type %d in a client Initial.'), $type)
                    );
                }
            }
            $packets[] = [
                'first' => $first, 'dcid' => $dcid, 'scid' => $scid, 'pn' => $pnBytes,
                'length' => substr($datagram, $lengthOffset, $pnOffset - $lengthOffset),
                'size' => strlen($plain), 'frames' => $frames, 'trailer' => $trailer,
            ];
        }
        ksort($stream);
        $hello = '';
        foreach ($stream as $offset => $data) {
            if ($offset > strlen($hello)) {
                throw new \RuntimeException(
                    gettext('The ClientHello is incomplete, paste all Initial datagrams of the client.')
                );
            }
            $hello = substr($hello, 0, $offset) . $data . substr($hello, $offset + strlen($data));
        }
        if (
            strlen($hello) < 4 || $hello[0] !== "\x01" ||
            strlen($hello) !== 4 + hexdec(bin2hex(substr($hello, 1, 3)))
        ) {
            throw new \RuntimeException(
                gettext('The ClientHello is incomplete, paste all Initial datagrams of the client.')
            );
        }

        /* the ClientHello with new values */
        $scidLength = strlen($packets[0]['scid']);
        $newDcid = self::randomBytes(strlen($dcid));
        $newScid = self::randomBytes($scidLength);
        $pos = 4 + 2 + 32;
        $sessionId = substr($hello, $pos + 1, ord($hello[$pos]));
        $pos += 1 + strlen($sessionId);
        $suites = substr($hello, $pos, 2 + unpack('n', substr($hello, $pos, 2))[1]);
        $pos += strlen($suites);
        $compression = substr($hello, $pos, 1 + ord($hello[$pos]));
        $pos += strlen($compression);
        $extensionsEnd = $pos + 2 + unpack('n', substr($hello, $pos, 2))[1];
        $pos += 2;
        $extensions = [];
        $grease = false;
        $named = false;
        /* GREASE values are random per connection: each value of the template gets a new one, equal values stay
         * equal (a key share and its group) and different ones stay different (Chromium's two GREASE extensions) */
        $greaseMap = [];
        $regrease = function ($value) use (&$greaseMap) {
            if (!self::isGrease($value)) {
                return $value;
            }
            while (!isset($greaseMap[$value])) {
                $nibble = random_int(0, 15);
                $new = ($nibble << 12) | 0x0a00 | ($nibble << 4) | 0x0a;
                if (!in_array($new, $greaseMap, true)) {
                    $greaseMap[$value] = $new;
                }
            }
            return $greaseMap[$value];
        };
        /* a list of 16 bit values behind a length of $prefix bytes, GREASE values replaced */
        $relist = function ($data, $prefix) use ($regrease) {
            $values = array_values(unpack('n*', substr($data, $prefix)) ?: []);
            return substr($data, 0, $prefix) . pack('n*', ...array_map($regrease, $values));
        };
        $suites = $relist($suites, 2);
        while ($pos + 4 <= $extensionsEnd) {
            [$type, $size] = array_values(unpack('n2', substr($hello, $pos, 4)));
            $data = substr($hello, $pos + 4, $size);
            $pos += 4 + $size;
            if (self::isGrease($type)) {
                $grease = true;
                $type = $regrease($type);
            } elseif ($type === 10 || $type === 13) {
                $data = $relist($data, 2);
            } elseif ($type === 43) {
                $data = $relist($data, 1);
            } elseif ($type === 41 || $type === 42) {
                throw new \RuntimeException(
                    gettext('The template resumes an earlier session, capture the first connection to a new server.')
                );
            } elseif ($type === 0) {
                $data = pack('n', strlen($sni) + 3) . "\x00" . pack('n', strlen($sni)) . $sni;
                $named = true;
            } elseif ($type === 51) {
                $shares = '';
                for ($i = 2; $i + 4 <= strlen($data);) {
                    [$group, $length] = array_values(unpack('n2', substr($data, $i, 4)));
                    $shares .= pack('nn', $regrease($group), $length) .
                        (self::isGrease($group) ? substr($data, $i + 4, $length) : self::randomBytes($length));
                    $i += 4 + $length;
                }
                $data = pack('n', strlen($shares)) . $shares;
            } elseif ($type === 57) {
                $params = '';
                for ($i = 0; $i < strlen($data);) {
                    $start = $i;
                    $id = self::readVarint($data, $i);
                    $idLength = $i - $start;
                    $length = self::readVarint($data, $i);
                    if ($id === 0x0f) {
                        $params .= self::varint($id) . self::varint($scidLength) . $newScid;
                    } elseif ($id >= 27 && ($id - 27) % 31 === 0 && $idLength <= 4) {
                        /* GREASE transport parameter (RFC 9000 section 18.1): a new 31 * N + 27 of the same size */
                        $max = [1 => 63, 2 => 16383, 4 => 1073741823][$idLength];
                        do {
                            $id = 31 * random_int(0, intdiv($max - 27, 31)) + 27;
                        } while (strlen(self::varint($id)) !== $idLength);
                        $params .= self::varint($id) . self::varint($length) . self::randomBytes($length);
                    } else {
                        $params .= substr($data, $start, $i - $start + $length);
                    }
                    $i += $length;
                }
                $data = $params;
            } elseif ($type === 0xfe0d && ($data[0] ?? '') === "\x00" && strlen($data) > 10) {
                /* ECH GREASE: outer type, cipher suite, config id, enc and payload are random in a real one */
                $encLength = unpack('n', substr($data, 6, 2))[1];
                $payloadLength = unpack('n', substr($data, 8 + $encLength, 2))[1];
                $data = substr($data, 0, 5) . self::randomBytes(1) .
                    pack('n', $encLength) . self::randomBytes($encLength) .
                    pack('n', $payloadLength) . self::randomBytes($payloadLength);
            }
            $extensions[] = [$type, $data];
        }
        if (!$named) {
            throw new \RuntimeException(gettext('The ClientHello of the template has no server name.'));
        }
        if ($grease) {
            /* Chromium shuffles its extensions on every connection, the GREASE ones keep their place */
            $slots = array_keys(array_filter($extensions, fn($ext) => !self::isGrease($ext[0])));
            $moved = array_map(fn($slot) => $extensions[$slot], $slots);
            for ($i = count($moved) - 1; $i > 0; $i--) {
                $j = random_int(0, $i);
                [$moved[$i], $moved[$j]] = [$moved[$j], $moved[$i]];
            }
            foreach ($slots as $idx => $slot) {
                $extensions[$slot] = $moved[$idx];
            }
        }
        $body = "\x03\x03" . self::randomBytes(32) . chr(strlen($sessionId)) . self::randomBytes(strlen($sessionId)) .
            $suites . $compression;
        $block = implode('', array_map(fn($ext) => pack('nn', $ext[0], strlen($ext[1])) . $ext[1], $extensions));
        $body .= pack('n', strlen($block)) . $block;
        $newHello = "\x01" . substr(pack('N', strlen($body)), 1) . $body;

        /* the frames keep their layout: every CRYPTO frame keeps its offset and length, except that the frame which
         * ends the ClientHello takes the difference in length (a shorter one may reach back into the frames before) */
        $ends = [];
        foreach ($packets as $pi => $packet) {
            foreach ($packet['frames'] as $fi => $frame) {
                if ($frame[0] === 'crypto') {
                    $ends["$pi:$fi"] = $frame[1] + $frame[2];
                }
            }
        }
        arsort($ends);
        $sizes = [];
        $delta = strlen($newHello) - strlen($hello);
        foreach ($ends as $ref => $end) {
            [$pi, $fi] = explode(':', $ref);
            $sizes[$ref] = max(0, $packets[$pi]['frames'][$fi][2] + $delta);
            $delta -= $sizes[$ref] - $packets[$pi]['frames'][$fi][2];
        }
        /* Chrome scatters the ClientHello (several CRYPTO frames, PING and PADDING in a random order, new on every
         * connection): a template that shows this gets a new layout of the same kind every time */
        $chaos = false;
        foreach ($packets as $packet) {
            $kinds = array_count_values(array_column($packet['frames'], 0));
            $chaos = $chaos || ($kinds['crypto'] ?? 0) > 1 || ($kinds['ping'] ?? 0) > 0;
        }
        $result = [];
        foreach ($packets as $pi => $packet) {
            $items = [];
            foreach ($packet['frames'] as $fi => $frame) {
                if ($frame[0] !== 'crypto') {
                    $items[] = $frame;
                } elseif ($sizes["$pi:$fi"] > 0) {
                    $items[] = ['crypto', $frame[1], $sizes["$pi:$fi"]];
                }
            }
            if ($chaos) {
                $items = self::scatter($items);
            }
            $payload = [];
            $pads = [];
            foreach ($items as $item) {
                if ($item[0] === 'pad') {
                    $pads[] = count($payload);
                    $payload[] = $item[1];
                } elseif ($item[0] === 'ping') {
                    $payload[] = "\x01";
                } else {
                    $payload[] = "\x06" . self::varint($item[1]) . self::varint($item[2]) .
                        substr($newHello, $item[1], $item[2]);
                }
            }
            /* the packet keeps its size: the padding takes up the difference, the longest run first (with a new
             * layout the runs get random sizes) */
            $used = array_sum(array_map(fn($part) => is_int($part) ? $part : strlen($part), $payload));
            $missing = $packet['size'] - $used;
            if (!$pads) {
                $pads[] = count($payload);
                $payload[] = 0;
            }
            if ($chaos && $missing >= -array_sum(array_map(fn($idx) => $payload[$idx], $pads))) {
                $total = array_sum(array_map(fn($idx) => $payload[$idx], $pads)) + $missing;
                $cuts = [0, $total];
                for ($i = 1; $i < count($pads); $i++) {
                    $cuts[] = random_int(0, $total);
                }
                sort($cuts);
                foreach ($pads as $n => $idx) {
                    $payload[$idx] = $cuts[$n + 1] - $cuts[$n];
                }
                $missing = 0;
            }
            usort($pads, fn($a, $b) => $payload[$b] <=> $payload[$a]);
            foreach ($pads as $idx) {
                $change = max($missing, -$payload[$idx]);
                $payload[$idx] += $change;
                $missing -= $change;
            }
            if ($missing !== 0) {
                throw new \RuntimeException(
                    gettext('The server name is too long for this template, the packets have no room left.')
                );
            }
            $plain = implode('', array_map(fn($part) => is_int($part) ? str_repeat("\x00", $part) : $part, $payload));

            [$key, $iv, $hp] = self::initialKeys($newDcid);
            $header = $packet['first'] . "\x00\x00\x00\x01" . chr(strlen($newDcid)) . $newDcid . chr($scidLength) .
                $newScid . "\x00" . $packet['length'];
            $pnOffset = strlen($header);
            $header .= $packet['pn'];
            $pn = (int)hexdec(bin2hex($packet['pn']));
            $nonce = substr($iv, 0, 4) . (substr($iv, 4) ^ pack('J', $pn));
            $tag = '';
            $sealed = openssl_encrypt($plain, 'aes-128-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $header, 16);
            $out = $header . $sealed . $tag;
            $mask = self::hpMask($hp, $out, $pnOffset);
            $out[0] = chr(ord($out[0]) ^ (ord($mask[0]) & 0x0f));
            for ($i = 0; $i < strlen($packet['pn']); $i++) {
                $out[$pnOffset + $i] = chr(ord($out[$pnOffset + $i]) ^ ord($mask[1 + $i]));
            }
            $result[] = $out . $packet['trailer'];
        }
        return $result;
    }

    /**
     * A new Chrome-style layout for the frames of one packet: the same part of the ClientHello cut at new places
     * into as many CRYPTO frames as before, with the same number of PING frames and PADDING runs (their sizes are
     * set later), all in a random order.
     */
    private static function scatter(array $items)
    {
        $kinds = array_count_values(array_column($items, 0));
        $pieces = [];
        foreach ($items as $item) {
            if ($item[0] === 'crypto') {
                $last = count($pieces) - 1;
                if ($last >= 0 && $pieces[$last][0] + $pieces[$last][1] === $item[1]) {
                    $pieces[$last][1] += $item[2];   /* contiguous parts join before they are cut again */
                } else {
                    $pieces[] = [$item[1], $item[2]];
                }
            }
        }
        usort($pieces, fn($a, $b) => $a[0] <=> $b[0]);
        while (count($pieces) < ($kinds['crypto'] ?? 0)) {
            $long = array_keys(array_filter($pieces, fn($piece) => $piece[1] > 1));
            if (!$long) {
                break;
            }
            $idx = $long[random_int(0, count($long) - 1)];
            $cut = random_int(1, $pieces[$idx][1] - 1);
            array_splice($pieces, $idx + 1, 0, [[$pieces[$idx][0] + $cut, $pieces[$idx][1] - $cut]]);
            $pieces[$idx][1] = $cut;
        }
        $result = array_map(fn($piece) => ['crypto', $piece[0], $piece[1]], $pieces);
        for ($i = 0; $i < ($kinds['ping'] ?? 0); $i++) {
            $result[] = ['ping'];
        }
        for ($i = 0; $i < ($kinds['pad'] ?? 0); $i++) {
            $result[] = ['pad', 0];
        }
        for ($i = count($result) - 1; $i > 0; $i--) {
            $j = random_int(0, $i);
            [$result[$i], $result[$j]] = [$result[$j], $result[$i]];
        }
        return $result;
    }

    /** SIP OPTIONS request (RFC 3261) */
    private static function sip()
    {
        $host = '192.168.' . random_int(1, 254) . '.' . random_int(2, 254);
        return self::text([
            'OPTIONS sip:', [random_int(5, 9)], '@', [random_int(6, 10)], ".com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {$host}:5060;branch=z9hG4bK", [10], "\r\n",
            "Max-Forwards: 70\r\n",
            'From: <sip:', [random_int(5, 9)], '@', [random_int(6, 10)], '.com>;tag=', [8], "\r\n",
            'To: <sip:', [random_int(5, 9)], '@', [random_int(6, 10)], ".com>\r\n",
            'Call-ID: ', [16], "@{$host}\r\n",
            "CSeq: 1 OPTIONS\r\n",
            "Content-Length: 0\r\n\r\n",
        ]);
    }

    /** STUN Binding request (RFC 5389) with a random transaction id */
    private static function stun()
    {
        return self::bytes("\x00\x01\x00\x00\x21\x12\xa4\x42") . self::random(12);
    }

    /** NTP version 4 client request (RFC 5905), the transmit timestamp is the current time */
    private static function ntp()
    {
        $header = "\x23\x00" . chr(random_int(6, 10)) . chr(random_int(0xe8, 0xec));
        return self::bytes($header . str_repeat("\x00", 36)) . '<t>' . self::random(4);
    }
}
