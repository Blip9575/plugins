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

use OPNsense\Core\Config;

/**
 * Defaults of the peer generator fields of an instance (endpoint, DNS, allowed IPs): the instance dialog fills them
 * into empty fields, the user can change them and saving stores them. The peer generator uses what is stored.
 */
class PeerDefaults
{
    public const ALLOWED_IPS = '0.0.0.0/0,::/0';

    /** the address of an interface (the PPPoE device on a PPPoE WAN), IPv6 in brackets, empty when it has none */
    public static function address($interface = 'wan')
    {
        $address = (string)SniSource::interfaceAddress($interface);
        return strpos($address, ':') !== false ? '[' . $address . ']' : $address;
    }

    /** the addresses of the interfaces the SNI source offers, for an endpoint that follows the SNI source */
    public static function addresses()
    {
        $result = [];
        foreach (array_keys(SniSource::interfaces()) as $interface) {
            $result[$interface] = self::address($interface);
        }
        return $result;
    }

    /** WAN address and listen port, the address alone when the port is not fixed */
    public static function endpoint($port)
    {
        $address = self::address();
        return $address !== '' && (string)$port !== '' ? $address . ':' . $port : $address;
    }

    /** the management address of the firewall on the LAN: its CARP address when there is one, else the LAN address */
    public static function dns()
    {
        $config = Config::getInstance()->object();
        foreach ($config->virtualip->vip ?? [] as $vip) {
            if (
                (string)$vip->mode === 'carp' && (string)$vip->interface === 'lan' &&
                strpos((string)$vip->subnet, ':') === false
            ) {
                return (string)$vip->subnet;
            }
        }
        $address = (string)($config->interfaces->lan->ipaddr ?? '');
        return filter_var($address, FILTER_VALIDATE_IP) ? $address : (string)SniSource::interfaceAddress('lan');
    }
}
