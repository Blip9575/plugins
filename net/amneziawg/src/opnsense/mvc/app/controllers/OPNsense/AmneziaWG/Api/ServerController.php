<?php

/*
 * Copyright (C) 2023 Deciso B.V.
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

namespace OPNsense\AmneziaWG\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Backend;
use OPNsense\AmneziaWG\ParamGenerator;
use OPNsense\AmneziaWG\SniSource;

class ServerController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'server';
    protected static $internalModelClass = '\OPNsense\AmneziaWG\Server';

    public function keyPairAction()
    {
        return json_decode((new Backend())->configdRun('amneziawg gen_keypair'), true);
    }

    /**
     * new random AmneziaWG 2.0 obfuscation parameters for the profile chosen in the instance dialog: none generates
     * nothing, random generates the parameters without a signature packet, a protocol (http3, quic, dns, ntp, stun, sip)
     * also sets I1 to a packet that imitates the start of a session of that protocol
     */
    public function genParamsAction($profile = 'random')
    {
        $profile = strtolower((string)$profile);
        if ($profile === 'none') {
            return ['status' => 'ok', 'params' => []];
        } elseif ($profile !== 'random' && !isset(ParamGenerator::PROTOCOLS[$profile])) {
            return ['status' => 'failed'];
        }

        $sni = null;
        $via = '';
        if ($profile === 'http3' || $profile === 'quic') {
            /* the server name comes from the SNI source of the dialog (query parameter source), without a fallback */
            try {
                [$sni, $via] = SniSource::resolve($this->request->get('source', null, 'wan'));
            } catch (\RuntimeException $e) {
                return ['status' => 'failed', 'message' => $e->getMessage()];
            }
            $sni = $sni ?? ParamGenerator::SNI[random_int(0, count(ParamGenerator::SNI) - 1)];
        }

        return ['status' => 'ok', 'params' => ParamGenerator::awg2($profile, $sni), 'sni' => (string)$sni, 'sni_via' => $via];
    }

    /**
     * options for the SNI source of the dialog, in the format of the net_selector widget: a manual entry, the
     * interfaces that have an address and the built-in list
     */
    public function getSniOptionsAction()
    {
        if (!$this->request->isGet()) {
            return ['status' => 'failed'];
        }
        return [
            'single' => ['label' => gettext('Manual entry: address or host name')],
            'interfaces' => ['label' => gettext('Interface address'), 'items' => SniSource::interfaces()],
            'other' => ['label' => gettext('Other'), 'items' => ['list' => gettext('Built-in list')]],
        ];
    }

    /**
     * new AmneziaWG 3.x parameters for the "Enable AmneziaWG 3.x" box of the instance dialog: a header protection key.
     * With prefixes set to 1 the S1-S4 prefix sizes are included too, the dialog asks for them when S1-S4 are empty or
     * below the 12 that header protection requires
     */
    public function genParams3Action($prefixes = '0')
    {
        return ['status' => 'ok', 'params' => ParamGenerator::awg3((string)$prefixes === '1')];
    }

    public function searchServerAction()
    {
        return $this->searchBase('servers.server');
    }

    public function getServerAction($uuid = null)
    {
        return $this->getBase('server', 'servers.server', $uuid);
    }

    public function addServerAction($uuid = null)
    {
        return $this->addBase('server', 'servers.server', $uuid);
    }

    public function delServerAction($uuid)
    {
        return $this->delBase('servers.server', $uuid);
    }

    public function setServerAction($uuid = null)
    {
        return $this->setBase('server', 'servers.server', $uuid);
    }

    public function toggleServerAction($uuid)
    {
        return $this->toggleBase('servers.server', $uuid);
    }
}
