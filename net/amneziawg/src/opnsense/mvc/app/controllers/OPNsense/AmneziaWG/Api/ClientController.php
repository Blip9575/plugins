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
use OPNsense\Core\Config;
use OPNsense\AmneziaWG\ParamGenerator;
use OPNsense\AmneziaWG\Server;
use OPNsense\Core\Backend;
use OPNsense\Firewall\Util;

class ClientController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'client';
    protected static $internalModelClass = '\OPNsense\AmneziaWG\Client';

    public function pskAction()
    {
        return ['psk' => trim((new Backend())->configdRun('amneziawg gen_psk')), 'status' => 'ok' ];
    }

    public function listServersAction()
    {
        if ($this->request->isGet()) {
            $results = ['rows' => [], 'status' => 'ok'];
            foreach ((new Server())->servers->server->iterateItems() as $key => $node) {
                $results['rows'][] = [
                    'uuid' => $key,
                    'name' => (string)$node->name
                ];
            }
            return $results;
        }
        return ['status' => 'failed'];
    }

    public function searchClientAction()
    {
        $servers = $this->request->get('servers');
        $filter_funct = function ($record) use ($servers) {
            return empty($servers) || array_intersect(explode(',', $record->servers), $servers);
        };

        return $this->searchBase('clients.client', null, null, $filter_funct);
    }

    public function getClientAction($uuid = null)
    {
        return $this->getBase('client', 'clients.client', $uuid);
    }

    public function addClientAction()
    {
        return $this->setClientAction(null);
    }

    public function delClientAction($uuid)
    {
        if ($this->request->isPost()) {
            Config::getInstance()->lock();
            $mdl = new Server();
            foreach ($mdl->servers->server->iterateItems() as $key => $node) {
                $peers = array_filter(explode(',', (string)$node->peers));
                if (in_array($uuid, $peers)) {
                    $node->peers = implode(',', array_diff($peers, [$uuid]));
                }
            }
            $mdl->serializeToConfig(false, true);
        }
        return $this->delBase('clients.client', $uuid);
    }

    public function setClientAction($uuid)
    {
        $add_uuid = null;
        if (!empty($this->request->getPost(static::$internalModelName)) && $this->request->isPost()) {
            $servers = [];
            if (!empty($this->request->getPost(static::$internalModelName)['servers'])) {
                $servers = explode(',', $this->request->getPost(static::$internalModelName)['servers']);
            }
            Config::getInstance()->lock();
            $mdl = new Server();
            if (empty($uuid)) {
                // add new client, generate uuid
                $uuid = $mdl->servers->generateUUID();
                $add_uuid = $uuid;
            }
            foreach ($mdl->servers->server->iterateItems() as $key => $node) {
                $peers = array_filter(explode(',', (string)$node->peers));
                if (in_array($uuid, $peers) && !in_array($key, $servers)) {
                    $node->peers = implode(',', array_diff($peers, [$uuid]));
                } elseif (!in_array($uuid, $peers) && in_array($key, $servers)) {
                    $node->peers = implode(',', array_merge($peers, [$uuid]));
                }
            }
            /**
             * Save to in memory model.
             * Ignore validations as $uuid might be new or trigger an existing validation issue.
             * Persisting the data is handled by setBase()
             */
            $mdl->serializeToConfig(false, true);
        }
        $result = $this->setBase('client', 'clients.client', $uuid);
        if (!empty($add_uuid) && $result['result'] == 'saved') {
            $result['uuid'] = $add_uuid;
        }
        return $result;
    }

    public function toggleClientAction($uuid)
    {
        return $this->toggleBase('clients.client', $uuid);
    }

    public function getClientBuilderAction()
    {
        return $this->getBase('configbuilder', 'clients.client', null);
    }

    public function addClientBuilderAction()
    {
        $uuid = null;
        if ($this->request->isPost() && !empty($this->request->getPost('configbuilder'))) {
            Config::getInstance()->lock();
            $mdl = new Server();
            $uuid = $this->getModel()->clients->generateUUID();
            $server = $this->request->getPost('configbuilder')['server'];
            foreach ($mdl->servers->server->iterateItems() as $key => $node) {
                if ($key == $server) {
                    $peers = array_filter(explode(',', (string)$node->peers));
                    $node->peers = implode(',', array_merge($peers, [$uuid]));
                    break;
                }
            }
            /**
             * Save to in memory model.
             * Ignore validations as $uuid might be new or trigger an existing validation issue.
             * Persisting the data is handled by setBase()
             */
            $mdl->serializeToConfig(false, true);
        }

        return $this->setBase('configbuilder', 'clients.client', $uuid);
    }

    /**
     * Signature packets of its own for a peer configuration: new I1-I5 of the instance's protocol profile, with the
     * server name and the Initial packet template of the instance. Only the sender uses them, so every peer can have
     * different ones. Null (the instance's own packets are used) without a protocol profile, without signature packets
     * on the instance, for HTTP/3 without a stored server name, or when the template can not be used.
     */
    private function peerSignature($node)
    {
        $protocol = (string)$node->awg2_profile;
        if (!isset(ParamGenerator::PROTOCOLS[$protocol]) || (string)$node->i1 === '') {
            return null;
        }
        $sni = null;
        if (in_array($protocol, ParamGenerator::INITIAL, true)) {
            $sni = (string)$node->sni_used;
            if ($sni === '') {
                return null;
            }
        }
        try {
            return ParamGenerator::signature($protocol, $sni, (string)$node->quic_template);
        } catch (\RuntimeException $e) {
            return null;
        }
    }

    public function getServerInfoAction($uuid = null)
    {
        $result = ['status' => 'failed'];
        if ($this->request->isGet()) {
            $peers = [];
            $subnets = [];
            $used_addresses = []; /* We cleanse addresses before storing here, to allow string matching */

            foreach ((new Server())->servers->server->iterateItems() as $key => $node) {
                if ($key == $uuid) {
                    $peers = array_filter(explode(',', (string)$node->peers));
                    $result['endpoint'] = (string)$node->endpoint;
                    $result['peer_dns'] = (string)$node->peer_dns;
                    $result['allowed_ips'] = (string)$node->allowed_ips;
                    $result['mtu'] = (string)$node->mtu;
                    $result['pubkey'] = (string)$node->pubkey;
                    /* config key => value, only for the options that are set; the signature packets are new for
                     * every peer configuration when the instance uses a protocol profile */
                    $result['awg'] = [];
                    $signature = $this->peerSignature($node);
                    foreach (
                        ['jc' => 'Jc', 'jmin' => 'Jmin', 'jmax' => 'Jmax', 's1' => 'S1', 's2' => 'S2', 's3' => 'S3',
                         's4' => 'S4', 'h1' => 'H1', 'h2' => 'H2', 'h3' => 'H3', 'h4' => 'H4', 'i1' => 'I1',
                         'i2' => 'I2', 'i3' => 'I3', 'i4' => 'I4', 'i5' => 'I5'] as $field => $name
                    ) {
                        $value = $signature !== null && isset($signature[$field]) ?
                            $signature[$field] : (string)$node->$field;
                        if ($value !== '') {
                            $result['awg'][$name] = $value;
                        }
                    }
                    /* the AmneziaWG 3.x options only count when they are enabled for the instance */
                    if ((string)$node->awg3_enabled === '1') {
                        foreach (
                            ['headerprotectionkey' => 'HeaderProtectionKey',
                             'contentpaddingaddition' => 'ContentPaddingAddition',
                             'rekeyaftertime' => 'RekeyAfterTime', 'rekeytimeout' => 'RekeyTimeout',
                             'rejectaftertime' => 'RejectAfterTime', 'keepalivetimeout' => 'KeepaliveTimeout',
                             'maxhandshakeattempts' => 'MaxHandshakeAttempts'] as $field => $name
                        ) {
                            if ((string)$node->$field !== '') {
                                $result['awg'][$name] = (string)$node->$field;
                            }
                        }
                        foreach (
                            ['randomtrailers' => 'RandomTrailers', 'disablecookies' => 'DisableCookies'] as $field => $name
                        ) {
                            if ((string)$node->$field === '1') {
                                $result['awg'][$name] = 'on';
                            }
                        }
                    }
                    foreach (array_filter(explode(',', (string)$node->tunneladdress)) as $addr) {
                        $proto = str_contains($addr, ':') ? 'inet6' : 'inet';
                        if (!isset($subnets[$proto])) {
                            $subnets[$proto] = $addr;
                        }
                        $used_addresses[] = inet_ntop(inet_pton(explode('/', $addr)[0]));
                    }
                    foreach ($peers as $peer) {
                        $this_peer = $this->getModel()->getNodeByReference('clients.client.' . $peer);
                        if ($this_peer != null) {
                            foreach (array_filter(explode(',', (string)$this_peer->tunneladdress)) as $addr) {
                                $used_addresses[] = inet_ntop(inet_pton(explode('/', $addr)[0]));
                            }
                        }
                    }
                    $tunneladdress = [];
                    foreach ($subnets as $cidr) {
                        foreach (Util::cidrRangeIterator($cidr) as $addr) {
                            if (!in_array($addr, $used_addresses)) {
                                $netmask = str_contains($addr, ':') ? '128' : '32';
                                $tunneladdress[] = $addr . '/' . $netmask;
                                break;
                            }
                        }
                    }
                    $result['address'] = implode(',', $tunneladdress);
                    $result['status'] = 'ok';
                    break;
                }
            }
        }
        return $result;
    }
}
