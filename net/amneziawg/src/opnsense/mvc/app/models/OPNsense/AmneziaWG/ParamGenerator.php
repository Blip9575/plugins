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
 * they have the layout of the protocol, they are not real sessions (the payload of a QUIC Initial is encrypted
 * with keys derived from its connection id, here it is random bytes). The <c> tag is not used, amneziawg-go does
 * not implement it.
 */
class ParamGenerator
{
    /* header ranges are picked from this span, small values are left to standard WireGuard message types */
    private const H_LOW = 100000;
    private const H_HIGH = 4294967295;

    /* imitated protocols with their usual UDP port, the dropdown of the instance dialog lists them as "DNS (53)" */
    public const PROTOCOLS = [
        'dns' => ['label' => 'DNS', 'port' => '53'],
        'ntp' => ['label' => 'NTP', 'port' => '123'],
        'quic' => ['label' => 'QUIC', 'port' => '443'],
        'sip' => ['label' => 'SIP', 'port' => '5060'],
        'stun' => ['label' => 'STUN', 'port' => '3478'],
    ];

    public static function awg2(string $protocol = '')
    {
        $result = [
            'jc' => (string)random_int(3, 10),
            'jmin' => (string)random_int(6, 10),
            'jmax' => (string)random_int(60, 100),
        ];

        $result += self::prefixes();

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
            $result['i1'] = self::$protocol();
        }

        return $result;
    }

    /**
     * Random prefix sizes S1-S4 (awg(8): S1/S2/S3 15-150 and S4 15-32), S1, S2 and S3 differ from each other and
     * S1 + 56 is not S2. Header protection needs S1-S4 of at least 12, these are always above that.
     */
    public static function prefixes()
    {
        do {
            $s = [random_int(15, 150), random_int(15, 150), random_int(15, 150)];
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

    /** QUIC version 1 Initial (RFC 9000): long header, 8 byte destination connection id, no token, 1200+ bytes */
    private static function quic()
    {
        $total = random_int(1200, 1252);
        $rest = $total - 18; /* everything after the length field: packet number and payload */
        return self::bytes(chr(0xC0 | random_int(0, 15)) . "\x00\x00\x00\x01\x08") . self::random(8) .
            self::bytes("\x00\x00" . pack('n', 0x4000 | $rest)) . self::random($rest);
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
