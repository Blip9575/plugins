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
use OPNsense\AmneziaWG\PeerDefaults;
use OPNsense\AmneziaWG\Server;
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
     * nothing, random generates the parameters without a signature packet, a protocol (http3, dns, ntp, stun, sip)
     * also sets I1 to a packet that imitates the start of a session of that protocol. The answer also carries the
     * listen port of the protocol and an MTU, and with the query parameter awg3=1 the AmneziaWG 3.x values of the
     * profile. The Initial packet template of the dialog comes in the POST body (template), see
     * ParamGenerator::templateInitials().
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
        if (in_array($profile, ParamGenerator::INITIAL, true)) {
            /* the server name comes from the SNI source of the dialog (query parameter source), without a fallback */
            try {
                [$sni, $via] = SniSource::resolve($this->request->get('source', null, 'wan'));
            } catch (\RuntimeException $e) {
                return ['status' => 'failed', 'message' => $e->getMessage()];
            }
            $sni = $sni ?? ParamGenerator::SNI[random_int(0, count(ParamGenerator::SNI) - 1)];
        }

        $awg3 = (string)$this->request->get('awg3', null, '0') === '1';
        try {
            $template = (string)$this->request->getPost('template', null, '');
            $params = ParamGenerator::profile($profile, $sni, $awg3, $template);
        } catch (\RuntimeException $e) {
            return ['status' => 'failed', 'message' => $e->getMessage(), 'field' => 'quic_template'];
        }
        return [
            'status' => 'ok',
            'params' => $params,
            'sni' => (string)$sni,
            'sni_via' => $via,
        ];
    }

    /**
     * options for the SNI source of the dialog, in the format of the net_selector widget: the manual entry (labelled
     * like the one of the firewall rules), the interfaces that have an address and the built-in list
     */
    public function getSniOptionsAction()
    {
        if (!$this->request->isGet()) {
            return ['status' => 'failed'];
        }
        return [
            'single' => ['label' => gettext('Single host or Network')],
            'interfaces' => ['label' => gettext('Interface address'), 'items' => SniSource::interfaces()],
            'other' => ['label' => gettext('Other'), 'items' => ['list' => gettext('Built-in list')]],
        ];
    }

    /**
     * new AmneziaWG 3.x parameters for the "Enable AmneziaWG 3.x" box of the instance dialog: a header protection key,
     * and the 3.x values of the profile in the query parameter profile (none: the key only).
     * With prefixes set to 1 the S1-S4 prefix sizes are included too, the dialog asks for them when S1-S4 are empty or
     * below the 12 that header protection requires
     */
    public function genParams3Action($prefixes = '0')
    {
        $params = ParamGenerator::awg3((string)$prefixes === '1');
        $profile = strtolower((string)$this->request->get('profile', null, 'none'));
        if ($profile === 'random' || isset(ParamGenerator::PROTOCOLS[$profile])) {
            $params += ParamGenerator::awg3Values($profile);
        }
        return ['status' => 'ok', 'params' => $params];
    }

    /**
     * what else uses a UDP port on this firewall, for the warning of the instance dialog: other AmneziaWG instances
     * (the query parameter instance is the one in the dialog), core WireGuard instances and local services. Nothing
     * is blocked, the user decides.
     */
    public function portUsersAction($port = '')
    {
        $users = [];
        if (!ctype_digit((string)$port) || (int)$port < 1 || (int)$port > 65535) {
            return ['status' => 'failed', 'users' => $users];
        }
        $self = (string)$this->request->get('instance', null, '');
        foreach ((new Server())->servers->server->iterateItems() as $node) {
            if ((string)$node->port === (string)$port && (string)$node->instance !== $self) {
                $users[] = sprintf(
                    gettext('AmneziaWG instance %s (awg%s)'),
                    (string)$node->name,
                    (string)$node->instance
                );
            }
        }
        if (class_exists('\OPNsense\Wireguard\Server')) {
            foreach ((new \OPNsense\Wireguard\Server())->servers->server->iterateItems() as $node) {
                if ((string)$node->port === (string)$port) {
                    $users[] = sprintf(
                        gettext('WireGuard instance %s (wg%s)'),
                        (string)$node->name,
                        (string)$node->instance
                    );
                }
            }
        }
        /* local services; tunnel sockets belong to the kernel and show as ?? */
        exec('/usr/bin/sockstat -46 -l -P udp -p ' . (int)$port . ' 2> /dev/null', $lines);
        foreach (array_slice($lines, 1) as $line) {
            $fields = preg_split('/\s+/', trim($line));
            if (count($fields) > 1 && $fields[1] !== '??') {
                $users[] = sprintf(gettext('the service %s'), $fields[1]);
            }
        }
        return ['status' => 'ok', 'users' => array_values(array_unique($users))];
    }

    /**
     * defaults of the peer generator fields for the instance dialog: the WAN address (the endpoint is that address and
     * the listen port), the DNS server and the allowed IPs. For HTTP/3 the endpoint follows the SNI source, so the
     * addresses of the interfaces and the built-in server names (never an endpoint) come along.
     */
    public function peerDefaultsAction()
    {
        return [
            'status' => 'ok',
            'address' => PeerDefaults::address(),
            'addresses' => PeerDefaults::addresses(),
            'builtin' => ParamGenerator::SNI,
            'peer_dns' => PeerDefaults::dns(),
            'allowed_ips' => PeerDefaults::ALLOWED_IPS,
        ];
    }

    public function searchServerAction()
    {
        return $this->searchBase('servers.server');
    }

    public function getServerAction($uuid = null)
    {
        return $this->getBase('server', 'servers.server', $uuid);
    }

    /**
     * The server name of the HTTP/3 signature packets needs a source that gives a name (there is no fallback), so
     * saving an HTTP/3 instance that has signature packets resolves the source of that instance (an instance with
     * nothing generated yet is not checked). This is not part of the model validation: instances saved before the
     * source existed count as changed there, so every save would validate all of them.
     * @return array|null the validation answer of the dialog, null when the source is fine or not used
     */
    protected function sniValidation()
    {
        $post = $this->request->getPost('server');
        if (
            is_array($post) && in_array($post['awg2_profile'] ?? '', ParamGenerator::INITIAL, true) &&
            trim((string)($post['i1'] ?? '')) !== ''
        ) {
            try {
                SniSource::resolve((string)($post['sni_source'] ?? ''));
            } catch (\RuntimeException $e) {
                return ['result' => 'failed', 'validations' => ['server.sni_source' => $e->getMessage()]];
            }
        }
        return null;
    }

    public function addServerAction($uuid = null)
    {
        return $this->sniValidation() ?? $this->addBase('server', 'servers.server', $uuid);
    }

    public function delServerAction($uuid)
    {
        return $this->delBase('servers.server', $uuid);
    }

    public function setServerAction($uuid = null)
    {
        return $this->sniValidation() ?? $this->setBase('server', 'servers.server', $uuid);
    }

    public function toggleServerAction($uuid)
    {
        return $this->toggleBase('servers.server', $uuid);
    }
}
