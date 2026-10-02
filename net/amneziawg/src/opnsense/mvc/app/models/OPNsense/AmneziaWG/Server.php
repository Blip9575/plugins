<?php

/*
 * Copyright (C) 2018 Michael Muenz <m.muenz@gmail.com>
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

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;

class Server extends BaseModel
{
    /**
     * cross-field rules for the AmneziaWG obfuscation parameters
     */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);

        foreach ($this->servers->server->iterateItems() as $node) {
            if (!$validateFullModel && !$node->isFieldChanged()) {
                continue;
            }
            $key = $node->__reference;

            /* junk packet sizes, documented as Jmin < Jmax */
            if (
                (string)$node->jmin !== '' && (string)$node->jmax !== '' &&
                (int)(string)$node->jmax > 0 && (int)(string)$node->jmin >= (int)(string)$node->jmax
            ) {
                $messages->appendMessage(new Message(gettext('Jmin must be smaller than Jmax.'), $key . '.jmin'));
            }

            /* message type headers: 5 to 4294967295 as documented in awg(8), ranges must not overlap */
            $ranges = [];
            foreach (['h1', 'h2', 'h3', 'h4'] as $field) {
                $value = (string)$node->$field;
                if ($value === '') {
                    continue;
                }
                $parts = explode('-', $value);
                $lo = (int)$parts[0];
                $hi = (int)end($parts);
                if ($lo < 5 || $lo > $hi || $hi > 4294967295) {
                    $messages->appendMessage(new Message(
                        gettext('Use a number or range from 5 to 4294967295, the start must not exceed the end.'),
                        $key . '.' . $field
                    ));
                    continue;
                }
                $ranges[$field] = [$lo, $hi];
            }
            $names = array_keys($ranges);
            foreach ($names as $idx => $a) {
                foreach (array_slice($names, $idx + 1) as $b) {
                    if ($ranges[$a][0] <= $ranges[$b][1] && $ranges[$b][0] <= $ranges[$a][1]) {
                        $messages->appendMessage(new Message(
                            gettext('Header ranges must not overlap.'),
                            $key . '.' . $b
                        ));
                    }
                }
            }

            /* AmneziaWG 3.x: header protection derives its nonce from the first 12 bytes of the S1-S4 prefixes */
            $hpk = (string)$node->headerprotectionkey;
            if ($hpk !== '') {
                if (strlen(base64_decode($hpk, true) ?: '') !== 32) {
                    $messages->appendMessage(new Message(
                        gettext('The header protection key must be a 32 byte base64 key.'),
                        $key . '.headerprotectionkey'
                    ));
                }
                foreach (['s1', 's2', 's3', 's4'] as $field) {
                    if ((int)(string)$node->$field < 12) {
                        $messages->appendMessage(new Message(
                            gettext('S1-S4 must be at least 12 when header protection is used.'),
                            $key . '.' . $field
                        ));
                    }
                }
            }

            /* AmneziaWG 3.x ranges are 16 bit */
            foreach (
                ['contentpaddingaddition', 'rekeyaftertime', 'rekeytimeout', 'rejectaftertime', 'keepalivetimeout',
                 'maxhandshakeattempts'] as $field
            ) {
                $value = (string)$node->$field;
                if ($value === '') {
                    continue;
                }
                $parts = explode('-', $value);
                if ((int)$parts[0] > (int)end($parts) || (int)end($parts) > 65535) {
                    $messages->appendMessage(new Message(
                        gettext('Invalid range, start must not exceed end and both must be at most 65535.'),
                        $key . '.' . $field
                    ));
                }
            }

            /* signature packets, kernel limit for AWG strings is 4096 */
            foreach (['i1', 'i2', 'i3', 'i4', 'i5'] as $field) {
                if (strlen((string)$node->$field) > 4096) {
                    $messages->appendMessage(new Message(
                        gettext('Value must not exceed 4096 characters.'),
                        $key . '.' . $field
                    ));
                }
                /* documented limit for the random byte tags <r N>, <rc N> and <rd N> */
                if (preg_match_all('/<(?:r|rc|rd) ([0-9]+)>/', (string)$node->$field, $tags) && max($tags[1]) > 1000) {
                    $messages->appendMessage(new Message(
                        gettext('Random byte tags must not exceed 1000.'),
                        $key . '.' . $field
                    ));
                }
            }
        }

        return $messages;
    }
}
