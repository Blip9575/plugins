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

            /* junk packet sizes */
            if ((string)$node->jmin !== '' && (string)$node->jmax !== '' && (int)(string)$node->jmin > (int)(string)$node->jmax) {
                $messages->appendMessage(new Message(gettext('Jmin must not be larger than Jmax.'), $key . '.jmin'));
            }
            if ((int)(string)$node->jc > 0 && (int)(string)$node->jmax === 0) {
                $messages->appendMessage(new Message(gettext('Jmax is required when Jc is set.'), $key . '.jmax'));
            }

            /* init and response packets must differ in size */
            if (
                (string)$node->s1 !== '' && (string)$node->s2 !== '' &&
                (int)(string)$node->s1 + 56 === (int)(string)$node->s2
            ) {
                $messages->appendMessage(new Message(gettext('S1 + 56 must not equal S2.'), $key . '.s2'));
            }

            /* message type headers: all or none, valid ranges, no overlaps */
            $ranges = [];
            $set = 0;
            foreach (['h1', 'h2', 'h3', 'h4'] as $field) {
                $value = (string)$node->$field;
                if ($value === '') {
                    continue;
                }
                $set++;
                $parts = explode('-', $value);
                $lo = (int)$parts[0];
                $hi = (int)end($parts);
                if ($lo > $hi || $hi > 4294967295) {
                    $messages->appendMessage(new Message(gettext('Invalid range, start must not exceed end and both must fit 32 bits.'), $key . '.' . $field));
                    continue;
                }
                $ranges[$field] = [$lo, $hi];
            }
            if ($set > 0 && $set < 4) {
                $messages->appendMessage(new Message(gettext('Set either all of H1-H4 or none of them.'), $key . '.h1'));
            }
            $names = array_keys($ranges);
            foreach ($names as $idx => $a) {
                foreach (array_slice($names, $idx + 1) as $b) {
                    if ($ranges[$a][0] <= $ranges[$b][1] && $ranges[$b][0] <= $ranges[$a][1]) {
                        $messages->appendMessage(new Message(gettext('Header ranges must not overlap.'), $key . '.' . $b));
                    }
                }
            }

            /* signature packets, kernel limit for AWG strings is 4096 */
            foreach (['i1', 'i2', 'i3', 'i4', 'i5'] as $field) {
                if (strlen((string)$node->$field) > 4096) {
                    $messages->appendMessage(new Message(gettext('Value must not exceed 4096 characters.'), $key . '.' . $field));
                }
            }
        }

        return $messages;
    }
}
