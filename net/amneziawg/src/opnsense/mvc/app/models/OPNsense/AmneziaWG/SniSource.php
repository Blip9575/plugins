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
 * Server name (SNI) for the HTTP/3 and QUIC signature packets. The source of an instance is
 *  - "list":                    the built-in list of ParamGenerator, a random one (resolve() gives null), only when chosen
 *  - an interface (wan, lan...): reverse lookup of its address
 *  - an IP address:              reverse lookup of that address
 *  - a host name:                used as typed
 * There is no fallback, not even for an empty source: when no name results the user is told to enter the correct address or host name.
 */
class SniSource
{
    /** interfaces that have an address, key => description, for the dropdown of the dialog */
    public static function interfaces()
    {
        $result = [];
        foreach (Config::getInstance()->object()->interfaces->children() as $key => $node) {
            if ((string)$node->if === '' || (string)$node->if === 'lo0' || (string)$node->ipaddr === '' && (string)$node->ipaddrv6 === '') {
                continue;
            }
            $result[$key] = (string)$node->descr !== '' ? (string)$node->descr : strtoupper($key);
        }
        return $result;
    }

    /** the first usable address of an interface: global IPv4, else global IPv6 */
    private static function interfaceAddress($key)
    {
        $device = (string)(Config::getInstance()->object()->interfaces->$key->if ?? '');
        if ($device === '') {
            return null;
        }
        $found = [];
        foreach (['inet', 'inet6'] as $family) {
            exec('/sbin/ifconfig ' . escapeshellarg($device) . ' ' . $family . ' 2> /dev/null', $lines);
            foreach ($lines ?? [] as $line) {
                if (preg_match('/^\s+' . $family . ' ([0-9a-fA-F:.]+)/', $line, $m)) {
                    $found[] = preg_replace('/%.*$/', '', $m[1]);
                }
            }
            $lines = [];
        }
        foreach ($found as $address) {
            if (self::isPublic($address)) {
                return $address;
            }
        }
        return $found[0] ?? null;
    }

    public static function isPublic($address)
    {
        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            if (!filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return false;
            }
            $long = ip2long($address);
            return !($long >= ip2long('100.64.0.0') && $long <= ip2long('100.127.255.255')); /* carrier grade NAT */
        }
        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return (bool)filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)
                && !preg_match('/^(fe[89ab]|fc|fd)/i', $address);
        }
        return false;
    }

    public static function isHostname($name)
    {
        return strlen($name) <= 253 && preg_match('/^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/', $name) === 1;
    }

    /** the name a reverse lookup of an address gives, null when there is none, uses host(1) with a short timeout */
    public static function reverse($address)
    {
        $process = proc_open(['/usr/bin/host', '-W', '3', $address], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($process)) {
            return null;
        }
        $output = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);
        if (preg_match('/domain name pointer ([^\s]+?)\.?\s*$/m', $output, $m)) {
            $name = strtolower(rtrim($m[1], '.'));
            if (self::isHostname($name) && !preg_match('/\.(in-addr|ip6)\.arpa$/', $name)) {
                return $name;
            }
        }
        return null;
    }

    /**
     * @return array [name or null for the built-in list, description of where it came from]
     * @throws \RuntimeException with the message the dialog shows
     */
    public static function resolve($source)
    {
        $source = trim((string)$source);
        if ($source === '') {
            throw new \RuntimeException(gettext('The SNI source is empty, enter an address or a host name in the text box.'));
        }
        if ($source === 'list') {
            return [null, gettext('built-in list')];
        }
        $label = null;
        if (isset(self::interfaces()[$source])) {
            $label = self::interfaces()[$source];
            $address = self::interfaceAddress($source);
            if ($address === null) {
                throw new \RuntimeException(sprintf(gettext('Interface %s has no address, enter the public address or a host name in the text box.'), $label));
            }
        } elseif (filter_var($source, FILTER_VALIDATE_IP)) {
            $address = $source;
        } elseif (self::isHostname($source)) {
            return [strtolower($source), gettext('typed host name')];
        } else {
            throw new \RuntimeException(sprintf(gettext('"%s" is not an interface, an address or a host name, enter the correct address or host name in the text box.'), $source));
        }
        if (!self::isPublic($address)) {
            throw new \RuntimeException($label !== null
                ? sprintf(gettext('%s assigned to %s is a private address, a reverse lookup has failed. Enter a public address or a host name in the text box.'), $address, $label)
                : sprintf(gettext('%s is a private address, a reverse lookup has failed. Enter a public address or a host name in the text box.'), $address));
        }
        $name = self::reverse($address);
        if ($name === null) {
            throw new \RuntimeException($label !== null
                ? sprintf(gettext('The reverse lookup of %s assigned to %s has failed. Enter a public address or a host name in the text box.'), $address, $label)
                : sprintf(gettext('The reverse lookup of %s has failed. Enter a public address or a host name in the text box.'), $address));
        }
        return [$name, $label !== null ? sprintf(gettext('reverse lookup of %s assigned to %s'), $address, $label) : sprintf(gettext('reverse lookup of %s'), $address)];
    }
}
