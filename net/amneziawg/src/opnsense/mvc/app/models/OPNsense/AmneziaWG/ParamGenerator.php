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
 * The signature packets I1-I5 are returned empty, a profile without them works on its own.
 */
class ParamGenerator
{
    /* header ranges are picked from this span, small values are left to standard WireGuard message types */
    private const H_LOW = 100000;
    private const H_HIGH = 4294967295;

    public static function awg2()
    {
        $result = [
            'jc' => (string)random_int(3, 10),
            'jmin' => (string)random_int(6, 10),
            'jmax' => (string)random_int(60, 100),
        ];

        do {
            $s = [random_int(15, 150), random_int(15, 150), random_int(15, 150)];
            $ok = count(array_unique($s)) === 3 && $s[0] + 56 !== $s[1];
        } while (!$ok);
        $result['s1'] = (string)$s[0];
        $result['s2'] = (string)$s[1];
        $result['s3'] = (string)$s[2];
        $result['s4'] = (string)random_int(15, 32);

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

        return $result;
    }
}
