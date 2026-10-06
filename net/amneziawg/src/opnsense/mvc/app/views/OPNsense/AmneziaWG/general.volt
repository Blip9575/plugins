{#
 # Copyright (c) 2014-2026 Deciso B.V.
 # Copyright (c) 2018 Michael Muenz <m.muenz@gmail.com>
 # All rights reserved.
 #
 # Redistribution and use in source and binary forms, with or without modification,
 # are permitted provided that the following conditions are met:
 #
 # 1.  Redistributions of source code must retain the above copyright notice,
 #     this list of conditions and the following disclaimer.
 #
 # 2.  Redistributions in binary form must reproduce the above copyright notice,
 #     this list of conditions and the following disclaimer in the documentation
 #     and/or other materials provided with the distribution.
 #
 # THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 # INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 # AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 # AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 # OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 # INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 # CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 # ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 # POSSIBILITY OF SUCH DAMAGE.
 #}

<script>
    $( document ).ready(function() {
        const data_get_map = {'frm_general_settings':"/api/amneziawg/general/get"};
        let configbuilder_reference = null;
        mapDataToFormUI(data_get_map).done(function(data){
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
        });

        const grid_peers = $("#{{formGridAmneziaWGClient['table_id']}}").UIBootgrid({
            search: '/api/amneziawg/client/search_client',
            get: '/api/amneziawg/client/get_client/',
            set: '/api/amneziawg/client/set_client/',
            add: '/api/amneziawg/client/add_client/',
            del: '/api/amneziawg/client/del_client/',
            toggle: '/api/amneziawg/client/toggle_client/',
            options: {
                initialSearchPhrase: getUrlHash('search'),
                requestHandler: function(request){
                    if ( $('#server_filter').val().length > 0) {
                        request['servers'] = $('#server_filter').val();
                    }
                    return request;
                }
            },
            commands: {
                show_peer: {
                    filter: (cell) => !!cell.getData().privkey,
                    classname: "fa fa-fw fa-qrcode",
                    title: "{{ lang._('Open in peer generator') }}",
                    sequence: 1000,
                    method: function(event, cell) {
                        configbuilder_reference = cell.getData();
                        $('a[href="#configbuilder"]').tab('show');
                    }
                },
                download_peer: {
                    filter: (cell) => !!cell.getData().privkey,
                    classname: "fa fa-fw fa-download",
                    title: "{{ lang._('Download configuration') }}",
                    sequence: 1001,
                    method: function(event, cell) {
                        const row = cell.getData();
                        ajaxGet('/api/amneziawg/client/get_server_info/' + row.servers, {}, function(data, status) {
                            if (data.status === 'ok') {
                                awg_download(buildPeerConfig({
                                    privkey: row.privkey,
                                    address: row.tunneladdress,
                                    peer_dns: data.peer_dns,
                                    mtu: data.mtu,
                                    pubkey: data.pubkey,
                                    awg: data.awg,
                                    psk: row.psk,
                                    endpoint: data.endpoint,
                                    allowedips: data.allowed_ips || "0.0.0.0/0,::/0",
                                    keepalive: row.keepalive
                                }), row.name);
                            }
                        });
                    }
                }
            },
        });
        grid_peers.on("loaded.rs.jquery.bootgrid", function (e){
            // reload servers before grid load
            if ($("#server_filter > option").length == 0) {
                ajaxGet('/api/amneziawg/client/list_servers', {}, function(data, status){
                    if (data.rows !== undefined) {
                        for (let i=0; i < data.rows.length ; ++i) {
                            let row = data.rows[i];
                            $("#server_filter").append($("<option/>").val(row.uuid).html(row.name));
                        }
                        $("#server_filter").selectpicker('refresh');
                    }
                });
            }
        });

        $("#{{formGridAmneziaWGServer['table_id']}}").UIBootgrid({
            search: '/api/amneziawg/server/search_server',
            get: '/api/amneziawg/server/get_server/',
            set: '/api/amneziawg/server/set_server/',
            add: '/api/amneziawg/server/add_server/',
            del: '/api/amneziawg/server/del_server/',
            toggle: '/api/amneziawg/server/toggle_server/',
            options: {
                formatters: {
                    /* the list holds the stored key of the profile, show its label and nothing for none */
                    awg2profile: function (column, row) {
                        const labels = {
                            random: 'Random', http3: 'HTTP/3 (443)', dns: 'DNS (53)',
                            ntp: 'NTP (123)', stun: 'STUN (3478)', sip: 'SIP (5060)'
                        };
                        return labels[row[column.id]] || '';
                    }
                }
            }
        });

        $("#reconfigureAct").SimpleActionButton({
            onPreAction: function() {
                const dfObj = new $.Deferred();
                saveFormToEndpoint("/api/amneziawg/general/set", 'frm_general_settings', function(){
                    dfObj.resolve();
                });
                return dfObj;
            }
        });

        /**
         * Move keypair generation button inside the instance form and hook api event
         */
        $("#control_label_server\\.pubkey").append($("#keygen_div").detach().show());
        /**
         * Parameter generators, like the keypair button. The gear on the AmneziaWG 2.0 row replaces Jc, Jmin, Jmax,
         * S1-S4 and H1-H4 with a new random profile for the protocol selected in the row (Random imitates no protocol
         * and clears I1-I5, a protocol also sets I1). Ticking "Enable AmneziaWG 3.x" asks whether to generate a new
         * header protection key and S1-S4 (only when they are below the 12 it requires), nothing is generated unless
         * the answer is yes. Nothing is saved before the dialog is saved, but peers of this instance stop working with
         * changed values, so the dialog always asks first and says so when peers are selected.
         */
        $("#control_label_server\\.awg2_profile").append($("#awg2gen_div").detach().show());
        /**
         * Header size per data packet, shown under the protocol row. WireGuard adds IP (20 IPv4, 40 IPv6) + UDP 8 + 32 = 60 / 80 bytes, AmneziaWG
         * adds S4 and, with AmneziaWG 3.x, the content padding (measured with amnezia-kmod 3.1.0, AmneziaWG/notes/06). The padding is a number
         * or a range a-b, a range adds a random amount.
         */
        const awg_header_update = function () {
            const s4 = parseInt($("#server\\.s4").val(), 10) || 0;
            const padding = $("#server\\.awg3_enabled").is(':checked') ? String($("#server\\.contentpaddingaddition").val() || '').match(/^([0-9]+)(?:-([0-9]+))?$/) : null;
            const lo = padding ? parseInt(padding[1], 10) : 0;
            const hi = padding ? parseInt(padding[2] || padding[1], 10) : 0;
            const total = function (base) {
                return lo === hi ? String(base + s4 + lo) : (base + s4 + lo) + "-" + (base + s4 + hi);
            };
            /* boxes without an id: the form does not send them */
            const box = function (value) {
                return $('<input type="text" readonly="readonly" class="form-control" style="display: inline-block; width: 9em; vertical-align: middle;"/>').val(value);
            };
            $("#server\\.header_size").empty().append("IPv4 ", box(total(60)), " IPv6 ", box(total(80)));
        };
        $("#server\\.s4, #server\\.contentpaddingaddition").on('input change', awg_header_update);
        $("#server\\.awg3_enabled").on('change', awg_header_update);
        $("#{{ formGridAmneziaWGServer['edit_dialog_id'] }}").on('shown.bs.modal', awg_header_update);
        /* the server name rows only matter for the HTTP/3 packets */
        const awg_sni_rows = function () {
            const quic = $("#server\\.awg2_profile").val() === 'http3';
            $("#row_server\\.sni_source, #row_server\\.sni_used, #row_server\\.quic_template").toggle(quic);
        };
        $("#server\\.awg2_profile").on('change', awg_sni_rows);
        $("#{{ formGridAmneziaWGServer['edit_dialog_id'] }}").on('shown.bs.modal', function () {
            awg_sni_rows();
            $("#server\\.sni_source").trigger('change');   /* lets the selector show the stored value */
        });
        /* the SNI source is a dropdown with a manual entry, like the address fields of the firewall rules */
        ajaxGet('/api/amneziawg/server/get_sni_options', {}, function (data, status) {
            if (data.single) {
                $(".net_selector").replaceInputWithSelector(data);
            }
        });
        /* no name could be made: switch the SNI source to the manual entry, a dropdown choice is cleared, typed text is kept */
        const awg_sni_manual = function () {
            const $selector = $("select[for='server.sni_source']");
            const typed = $selector.val() === '<<empty_item>>';
            $selector.val('<<empty_item>>').selectpicker('refresh').trigger('change');
            if (!typed) {
                $("#server\\.sni_source").val('');
            }
        };
        /* saving an HTTP/3 instance checks the source too: when core marks the row with an error, show the box */
        new MutationObserver(function () {
            if ($("#row_server\\.sni_source").hasClass('has-error')) {
                awg_sni_manual();
                $("#server\\.sni_source").focus();
            }
        }).observe($("#row_server\\.sni_source")[0], {attributes: true, attributeFilter: ['class']});
        const awg_params_url = function (profile) {
            return "/api/amneziawg/server/gen_params/" + profile + "?source=" + encodeURIComponent($("#server\\.sni_source").val() || '') +
                "&awg3=" + ($("#server\\.awg3_enabled").is(':checked') ? '1' : '0');
        };
        /* another instance or a local service on the same UDP port: a warning, the user resolves it */
        const awg_port_check = function (port) {
            if (!/^[0-9]+$/.test(String(port || ''))) {
                return;
            }
            ajaxGet('/api/amneziawg/server/port_users/' + port, {instance: $("#server\\.instance").val() || ''}, function (data, status) {
                if (data.users && data.users.length > 0) {
                    const $list = $("<ul></ul>");
                    $.each(data.users, function (idx, user) {
                        $list.append($("<li></li>").text(htmlDecode(user)));
                    });
                    stdDialogInform(
                        "{{ lang._('Listen port in use') }}",
                        $("<div></div>").append($("<p></p>").text("{{ lang._('UDP port %s is also used by:') }}".replace('%s', port))).append($list)
                            .append($("<p></p>").text("{{ lang._('Only one of them can receive the traffic. Choose another listen port here or change the other one.') }}")),
                        "{{ lang._('Close') }}", undefined, "warning"
                    );
                }
            });
        };
        /* defaults of the peer generator fields: filled into empty fields when the dialog has its data. The endpoint is
         * host and listen port and follows them as long as it still holds the value it was given.
         * Host: the WAN address, for HTTP/3 the SNI source, so the client looks up the same name a browser would
         * (see awg_endpoint_host) */
        let awg_wan = '';
        let awg_addresses = {};
        let awg_builtin = [];
        const awg_endpoint_host = function () {
            const source = String($("#server\\.sni_source").val() || '').trim();
            if ($("#server\\.awg2_profile").val() !== 'http3' || source === '' || source === 'list') {
                return awg_wan;   /* the built-in names are not this firewall */
            } else if (/^[0-9.]+$/.test(source)) {
                return source;
            } else if (source.indexOf(':') !== -1) {
                return '[' + source + ']';
            } else if (source.indexOf('.') !== -1) {
                return source.toLowerCase();   /* a host name, used as typed like the SNI */
            }
            /* an interface: the name the gear put in the packets (its reverse lookup), before that its address */
            const used = String($("#server\\.sni_used").val() || '');
            if (used !== '' && !awg_builtin.includes(used)) {
                return used;
            }
            return awg_addresses[source] || awg_wan;
        };
        const awg_endpoint_sync = function () {
            const $endpoint = $("#server\\.endpoint");
            if ($endpoint.val() === '' || $endpoint.val() === $endpoint.data('awg-default')) {
                const host = awg_endpoint_host();
                const port = String($("#server\\.port").val() || '').trim();
                const value = host !== '' && port !== '' ? host + ':' + port : host;
                $endpoint.val(value).data('awg-default', value);
            }
        };
        $("#server\\.sni_source, #server\\.awg2_profile").on('change', awg_endpoint_sync);
        $("#{{ formGridAmneziaWGServer['edit_dialog_id'] }}").on('opnsense_bootgrid_mapped', function () {
            $("#server\\.endpoint").removeData('awg-default');
            ajaxGet('/api/amneziawg/server/peer_defaults', {}, function (data, status) {
                if (data.status !== 'ok') {
                    return;
                }
                awg_wan = htmlDecode(data.address || '');
                awg_addresses = data.addresses || {};
                awg_builtin = data.builtin || [];
                awg_endpoint_sync();
                $.each({peer_dns: data.peer_dns, allowed_ips: data.allowed_ips}, function (field, value) {
                    const $field = $("#server\\." + field);
                    if ($field.val() === '' && value) {
                        $field.val(htmlDecode(value));
                    }
                });
            });
        });
        $("#server\\.port").on('change', function (e) {
            awg_endpoint_sync();
            /* typed by the user, not set by the form loader or the gear (they trigger no browser event) */
            if (e.originalEvent) {
                awg_port_check($(this).val());
            }
        });
        const awg_generate = function (url, message, on_cancel) {
            const apply = function () {
                /* gen_params is a POST: the Initial packet template is too long for a URL */
                const post = url.indexOf("/gen_params/") !== -1;
                const send = post ? {template: $("#server\\.quic_template").val() || ''} : {};
                (post ? ajaxCall : ajaxGet)(url, send, function (data, status) {
                    if (data.status && data.status === 'ok') {
                        $.each(data.params, function (field, value) {
                            const $field = $("#server\\." + field);
                            if ($field.is(':checkbox')) {
                                $field.prop('checked', value === '1');
                            } else {
                                /* the response is HTML escaped for the browser, I1 contains angle brackets */
                                $field.val(htmlDecode(value));
                            }
                        });
                        if (url.indexOf('/gen_params/') !== -1) {
                            $("#server\\.sni_used").val(htmlDecode(data.sni || ''));
                        }
                        /* after the server name: the endpoint may follow it */
                        awg_endpoint_sync();
                        if (data.params.port) {
                            awg_port_check(data.params.port);
                        }
                        awg_header_update();
                    } else if (data.message) {
                        /* the field the message is about: the SNI source (default) or the Initial packet template */
                        const field = data.field === 'quic_template' ? 'quic_template' : 'sni_source';
                        if (field === 'sni_source') {
                            awg_sni_manual();
                        }
                        stdDialogInform(
                            "{{ lang._('Nothing was changed') }}", $("<div></div>").text(htmlDecode(data.message)),
                            "{{ lang._('Close') }}", function () { $("#server\\." + field).focus(); }, "warning"
                        );
                    }
                });
            };
            const peers = $("#server\\.peers").val();
            if (peers && peers.length > 0) {
                message += " {{ lang._('This instance has peers. They stop connecting until they use a new configuration with the new values.') }}";
            }
            BootstrapDialog.confirm({
                title: "{{ lang._('Generate new parameters') }}",
                message: message,
                type: BootstrapDialog.TYPE_WARNING,
                btnCancelLabel: "{{ lang._('Cancel') }}",
                btnOKLabel: "{{ lang._('Yes') }}",
                btnOKClass: 'btn-warning',
                callback: function (result) {
                    if (result) {
                        apply();
                    } else if (on_cancel) {
                        on_cancel();
                    }
                }
            });
        };
        /* what the gear replaces for the selected profile, for the confirmation */
        const awg_params_message = function () {
            let message = "{{ lang._('Generate new parameters? The AmneziaWG 2.0 parameters (Jc, Jmin, Jmax, S1-S4, H1-H4 and I1-I5), the listen port of the protocol and the MTU are replaced.') }}";
            if ($("#server\\.awg3_enabled").is(':checked')) {
                message += " {{ lang._('AmneziaWG 3.x is enabled: the header protection key, RekeyAfterTime, RejectAfterTime, ContentPaddingAddition and RandomTrailers are replaced too.') }}";
            }
            return message + " {{ lang._('A changed listen port needs a matching firewall rule.') }}";
        };
        /* a new protocol needs matching parameters, a user selection asks for them, cancelling keeps the old selection */
        $("#server\\.awg2_profile").on('changed.bs.select', function (e, clickedIndex, isSelected, previousValue) {
            const profile = $(this).val();
            /* the event also follows programmatic changes, as when core loads the form: only a clicked option counts */
            if (typeof clickedIndex !== 'number' || !profile || profile === 'none' || profile === previousValue) {
                return;
            }
            /* a protocol profile uses AmneziaWG 3.x: the box is ticked before the question, so the values include it */
            const $awg3 = $("#server\\.awg3_enabled");
            const awg3_before = $awg3.is(':checked');
            if (profile !== 'random') {
                $awg3.prop('checked', true);
                awg_header_update();
            }
            awg_generate(
                awg_params_url(profile),
                awg_params_message() + " {{ lang._('Cancel returns to the previous selection.') }}",
                function () {
                    /* val() of selectpicker would fire the event again */
                    $("#server\\.awg2_profile").val(previousValue).selectpicker('refresh');
                    $awg3.prop('checked', awg3_before);
                    awg_header_update();
                }
            );
        });
        $("#awg2gen").click(function () {
            const profile = $("#server\\.awg2_profile").val();
            if (!profile || profile === 'none') {
                stdDialogInform(
                    "{{ lang._('No UDP protocol selected') }}",
                    "{{ lang._('Select Random or a UDP protocol to mimic first.') }}",
                    "{{ lang._('Close') }}", undefined, "warning"
                );
                return;
            }
            awg_generate(
                awg_params_url(profile),
                awg_params_message()
            );
        });
        /* click, not change: loading the form sets the box without a click. Ticking and clearing both change what the instance sends,
         * so both ask: ticked generates a header protection key (and S1-S4 when needed), cleared generates a new AmneziaWG 2.0 profile */
        $("#server\\.awg3_enabled").on('click', function () {
            if ($(this).is(':checked')) {
                const prefixes = ['s1', 's2', 's3', 's4'];
                const need_prefixes = prefixes.some(function (field) {
                    const value = parseInt($("#server\\." + field).val(), 10);
                    return isNaN(value) || value < 12;
                });
                awg_generate(
                    "/api/amneziawg/server/gen_params3/" + (need_prefixes ? '1' : '0') + "?profile=" + encodeURIComponent($("#server\\.awg2_profile").val() || 'none'),
                    "{{ lang._('Generate new parameters now? A new header protection key is generated, and S1-S4 when they are below 12. With a profile selected, RekeyAfterTime, RejectAfterTime, ContentPaddingAddition and RandomTrailers are set for it. Existing values are replaced.') }}"
                );
            } else {
                const profile = $("#server\\.awg2_profile").val();
                awg_generate(
                    awg_params_url(profile && profile !== 'none' ? profile : 'random'),
                    "{{ lang._('Generate new parameters now? AmneziaWG 3.x is switched off, its values are kept but not used. A new AmneziaWG 2.0 profile is generated for the selected protocol (Random when none is selected), the AmneziaWG 2.0 parameters are replaced.') }}"
                );
            }
        });
        $("#keygen").click(function(){
            ajaxGet("/api/amneziawg/server/key_pair", {}, function(data, status){
                if (data.status && data.status === 'ok') {
                    $("#server\\.pubkey").val(data.pubkey);
                    $("#server\\.privkey").val(data.privkey);
                }
            });
        })
        $("#control_label_client\\.psk").append($("#pskgen_div").detach().show());
        $("#pskgen").click(function(){
            ajaxGet("/api/amneziawg/client/psk", {}, function(data, status){
                if (data.status && data.status === 'ok') {
                    $("#client\\.psk").val(data.psk);
                }
            });
        })

        /**
         * Quick instance filter on top
         */
        $("#filter_container").detach().insertAfter('#{{formGridAmneziaWGClient["table_id"]}}-header .search');
        $("#server_filter").change(function(){
            $('#{{formGridAmneziaWGClient['table_id']}}').bootgrid('reload');
        });

        /**
         * Build the peer config for the peer generator
         */
        function buildPeerConfig(data)
        {
            let rows = [];
            rows.push('[Interface]');
            rows.push('PrivateKey = ' + data.privkey);
            if (data.address) {
                rows.push('Address = ' + data.address);
            }
            if (data.peer_dns) {
                rows.push('DNS = ' + data.peer_dns);
            }
            if (data.mtu) {
                rows.push('MTU = ' + data.mtu);
            }
            $.each(data.awg || {}, function (key, value) {
                rows.push(key + ' = ' + htmlDecode(value));
            });
            rows.push('');
            rows.push('[Peer]');
            rows.push('PublicKey = ' + data.pubkey);
            if (data.psk) {
                rows.push('PresharedKey = ' + data.psk);
            }
            rows.push('Endpoint = ' + data.endpoint);
            rows.push('AllowedIPs = ' + data.allowedips);
            if (data.keepalive) {
                rows.push('PersistentKeepalive = ' + data.keepalive);
            }
            return rows.join("\n");
        }

        /**
         * Load instance information for the peer generator
         */
        function configbuilder_load_server(server_id, callback, update_address = true)
        {
            ajaxGet('/api/amneziawg/client/get_server_info/' + server_id, {}, function(data, status) {
                if (data.status === 'ok') {
                    let endpoint = $("#configbuilder\\.endpoint");
                    let peer_dns = $("#configbuilder\\.peer_dns");
                    let allowed_ips = $("#configbuilder\\.tunneladdress");

                    if (update_address) {
                        $("#configbuilder\\.address").val(data.address);
                    }

                    peer_dns
                        .val(data.peer_dns)
                        .data('org-value', data.peer_dns);

                    endpoint
                        .val(data.endpoint)
                        .data('org-value', data.endpoint)
                        .data('mtu', data.mtu)
                        .data('pubkey', data.pubkey)
                        .data('awg', data.awg);

                    const allowed_ips_value = data.allowed_ips || "0.0.0.0/0,::/0";
                    allowed_ips
                        .val(allowed_ips_value)
                        .data('org-value', allowed_ips_value);

                    if (callback) {
                        callback();
                    }

                    endpoint.change();
                }
            });
        }

        /**
         * Toggle peer generator reference mode
         */
        function configbuilder_set_reference_mode(enabled)
        {
            $("#configbuilder\\.name").prop("disabled", enabled);

            [
                "servers",
                "endpoint",
                "peer_dns",
                "tunneladdress",
                "keepalive",
                "pubkey",
                "privkey",
                "psk",
                "address",
                "store_privkey",
                "actions"
            ].forEach(function(field) {
                $("#row_configbuilder\\." + field).toggle(!enabled);
            });

            $("#pskgen_cb").toggle(!enabled);
        }

        /**
         * Load an existing peer into the peer generator
         */
        function configbuilder_load_reference(row)
        {
            const server_id = row.servers;

            $("#configbuilder\\.servers")
                .val(server_id)
                .selectpicker('refresh');

            $("#configbuilder\\.name").val(row.name);
            $("#configbuilder\\.pubkey").val(row.pubkey);
            $("#configbuilder\\.privkey").val(row.privkey);
            $("#configbuilder\\.psk").val(row.psk);
            $("#configbuilder\\.address").val(row.tunneladdress);
            $("#configbuilder\\.keepalive").val(row.keepalive);

            configbuilder_load_server(server_id, function() {
                configbuilder_set_reference_mode(true);
            }, false);
        }

        /**
         * Peer generator tab hooks
         */
        $("#control_label_configbuilder\\.psk").append($("#pskgen_cb_div").detach().show());
        $("#pskgen_cb").click(function(){
            ajaxGet("/api/amneziawg/client/psk", {}, function(data, status){
                if (data.status && data.status === 'ok') {
                    $("#configbuilder\\.psk").val(data.psk).change();
                }
            });
        })
        $("#configbuilder\\.output").css('max-width', '100%');
        $("#configbuilder\\.output").css('height', '256px');
        $("#configbuilder\\.output").on('input', function() {
            const config = $(this).val();
            try {
                $("#configbuilder\\.qrcode").empty().qrcode(config);
            } catch (e) {
                /* a QR code holds a few kilobytes, signature packets of the HTTP/3 profile can exceed that */
                $("#configbuilder\\.qrcode").empty().append(
                    $("<p></p>").text(
                        "{{ lang._('This configuration is too large for a QR code') }} (" + new Blob([config]).size +
                        " {{ lang._('bytes') }}). {{ lang._('Download it as a file and import the file in the app. The file contains the private key.') }}"
                    ),
                    $('<button type="button" class="btn btn-default awg_download"></button>')
                        .append('<i class="fa fa-fw fa-download"></i> {{ lang._('Download') }}')
                );
            }
        });

        /**
         * Save a configuration as a file after a warning, the file contains the private key of the peer. Used by the
         * peers list and by the message that replaces a QR code which does not fit
         */
        const awg_download = function (config, peer_name) {
            const name = String(peer_name || '').replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^\.+/, '');
            stdDialogConfirm(
                "{{ lang._('Download configuration') }}",
                "{{ lang._('This file contains the private key of the peer. Keep it secure and delete it after importing it.') }}",
                "{{ lang._('Download') }}", "{{ lang._('Cancel') }}",
                function () {
                    const link = $('<a></a>')
                        .attr('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(config))
                        .attr('download', (name || 'amneziawg') + '.conf')
                        .appendTo('body');
                    link[0].click();
                    link.remove();
                }
            );
        };
        $(document).on('click', '.awg_download', function () {
            awg_download($("#configbuilder\\.output").val(), $("#configbuilder\\.name").val());
        });

        $("#configbuilder\\.servers").change(function(){
            configbuilder_load_server($(this).val());
        });

        $("#btn_configbuilder_cancel").click(function() {
            $('a[href="#peers"]').tab('show');
        });

        $("#btn_configbuilder_save").click(function(){
            if (configbuilder_reference !== null) {
                return;
            }
            let instance_id = $("#configbuilder\\.servers").val();
            let endpoint = $("#configbuilder\\.endpoint");
            let peer_dns = $("#configbuilder\\.peer_dns");
            let allowed_ips = $("#configbuilder\\.tunneladdress");
            let peer = {
                configbuilder: {
                    enabled: '1',
                    name: $("#configbuilder\\.name").val(),
                    pubkey: $("#configbuilder\\.pubkey").val(),
                    privkey: $("#configbuilder\\.store_privkey").prop("checked")
                        ? $("#configbuilder\\.privkey").val()
                        : '',
                    psk: $("#configbuilder\\.psk").val(),
                    tunneladdress: $("#configbuilder\\.address").val(),
                    keepalive: $("#configbuilder\\.keepalive").val(),
                    server: instance_id,
                    endpoint: endpoint.val()
                }
            };
            ajaxCall('/api/amneziawg/client/add_client_builder', peer, function(data, status) {
                if (data.validations) {
                    if (data.validations['configbuilder.tunneladdress']) {
                        /*
                         * tunnel address for the client is this peers address, since we remap these
                         * in the form, we should remap the errors as well.
                         */
                        data.validations['configbuilder.address'] = data.validations['configbuilder.tunneladdress'];
                        delete data.validations['configbuilder.tunneladdress'];
                    }
                    handleFormValidation("frm_config_builder", data.validations);
                } else {
                    $(document).trigger("settings-changed");
                    if (
                        endpoint.val() != endpoint.data('org-value') ||
                        peer_dns.val() != peer_dns.data('org-value') ||
                        allowed_ips.val() != allowed_ips.data('org-value')
                    ) {
                        let param = {
                            'server': {
                                'endpoint': endpoint.val(),
                                'peer_dns': peer_dns.val(),
                                'allowed_ips': allowed_ips.val()
                            }
                        };
                        ajaxCall('/api/amneziawg/server/set_server/' + instance_id, param, function(data, status){
                            configbuilder_new();
                        });
                    } else {
                        configbuilder_new();
                    }
                }
            });
        });
        $('input[id ^= "configbuilder\\."]').change(configbuilder_update_config);
        $('select[id ^= "configbuilder\\."]').change(configbuilder_update_config);

        function configbuilder_new()
        {
            configbuilder_reference = null;
            configbuilder_set_reference_mode(false);

            mapDataToFormUI({'frm_config_builder':"/api/amneziawg/client/get_client_builder"}).done(function(data){
                formatTokenizersUI();
                $('.selectpicker').selectpicker('refresh');
                // Private key storage is intentionally opt-in to preserve existing behavior.
                $("#configbuilder\\.store_privkey").prop("checked", false);
                ajaxGet("/api/amneziawg/server/key_pair", {}, function(data, status){
                    if (data.status && data.status === 'ok') {
                        $("#configbuilder\\.pubkey").val(data.pubkey);
                        $("#configbuilder\\.privkey").val(data.privkey).change();
                    }
                });
                /* a new peer gets signature packets of its own (get_server_info makes new ones on every call) */
                const server_id = $("#configbuilder\\.servers").val();
                if (server_id) {
                    ajaxGet('/api/amneziawg/client/get_server_info/' + server_id, {}, function (data, status) {
                        if (data.status === 'ok') {
                            $("#configbuilder\\.endpoint").data('awg', data.awg);
                            configbuilder_update_config();
                        }
                    });
                }
                clearFormValidation("frm_config_builder");
            });
        }

        function configbuilder_update_config()
        {
            const config = buildPeerConfig({
                privkey: $("#configbuilder\\.privkey").val(),
                address: $("#configbuilder\\.address").val(),
                peer_dns: $("#configbuilder\\.peer_dns").val(),
                mtu: $("#configbuilder\\.endpoint").data('mtu'),
                pubkey: $("#configbuilder\\.endpoint").data('pubkey'),
                awg: $("#configbuilder\\.endpoint").data('awg'),
                psk: $("#configbuilder\\.psk").val(),
                endpoint: $("#configbuilder\\.endpoint").val(),
                allowedips: $("#configbuilder\\.tunneladdress").val(),
                keepalive: $("#configbuilder\\.keepalive").val()
            });

            $("#configbuilder\\.output").val(config).trigger('input');
        }

        const $apply_container = $("#reconfigureAct").closest(".alert.content-box");

        $('a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
            if (e.target.id == 'tab_configbuilder') {
                if (configbuilder_reference !== null) {
                    configbuilder_load_reference(configbuilder_reference);
                    $apply_container.hide();
                } else {
                    configbuilder_new();
                    $apply_container.show();
                }
                $('#frm_general_settings').parent().hide();
            } else {
                configbuilder_reference = null;
                $apply_container.show();
                $('#{{formGridAmneziaWGClient['table_id']}}').bootgrid('reload');
                $('#frm_general_settings').parent().show();
            }
        });

        // update history on tab state and implement navigation
        if(window.location.hash != "") {
            $('a[href="' + window.location.hash + '"]').click()
        }
        $('.nav-tabs a').on('shown.bs.tab', function (e) {
            history.pushState(null, null, e.target.hash);
        });
        $(window).on('hashchange', function(e) {
            $('a[href="' + window.location.hash + '"]').click()
        });
    });
</script>

<!-- Navigation bar -->
<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" id="tab_instances" href="#instances">{{ lang._('Instances') }}</a></li>
    <li><a data-toggle="tab" id="tab_peers" href="#peers">{{ lang._('Peers') }}</a></li>
    <li><a data-toggle="tab" id="tab_configbuilder" href="#configbuilder">{{ lang._('Peer generator') }}</a></li>
</ul>

<div class="tab-content content-box tab-content">
    <div id="peers" class="tab-pane fade in">
        <span id="pskgen_div" style="display:none" class="pull-right">
            <button id="pskgen" type="button" class="btn btn-secondary" title="{{ lang._('Generate new psk.') }}" data-toggle="tooltip">
              <i class="fa fa-fw fa-gear"></i>
            </button>
        </span>
        <div class="hidden">
            <!-- filter per server container -->
            <div id="filter_container" class="btn-group">
                <select id="server_filter"  data-title="{{ lang._('Instances') }}" class="selectpicker" data-live-search="true" data-size="5"  multiple data-width="200px">
                </select>
            </div>
        </div>
        {{ partial('layout_partials/base_bootgrid_table', formGridAmneziaWGClient + {'command_width':'150'}) }}
    </div>
    <div id="instances" class="tab-pane fade in active">
        <span id="keygen_div" style="display:none" class="pull-right">
            <button id="keygen" type="button" class="btn btn-secondary" title="{{ lang._('Generate new keypair.') }}" data-toggle="tooltip">
              <i class="fa fa-fw fa-gear"></i>
            </button>
        </span>
        <span id="awg2gen_div" style="display:none" class="pull-right">
            <button id="awg2gen" type="button" class="btn btn-secondary" title="{{ lang._('Generate new parameters') }}" data-toggle="tooltip">
              <i class="fa fa-fw fa-gear"></i>
            </button>
        </span>
        {{ partial('layout_partials/base_bootgrid_table', formGridAmneziaWGServer)}}
    </div>
    <div id="configbuilder" class="tab-pane fade in">
        <span id="pskgen_cb_div" style="display:none" class="pull-right">
            <button id="pskgen_cb" type="button" class="btn btn-secondary" title="{{ lang._('Generate new psk.') }}" data-toggle="tooltip">
              <i class="fa fa-fw fa-gear"></i>
            </button>
        </span>
        {{ partial("layout_partials/base_form",['fields':formDialogConfigBuilder,'id':'frm_config_builder'])}}
    </div>
</div>
<div class="tab-content content-box tab-content __mt">
    {{ partial("layout_partials/base_form",['fields':generalForm,'id':'frm_general_settings'])}}
</div>
{{ partial('layout_partials/base_apply_button', {'data_endpoint': '/api/amneziawg/service/reconfigure'}) }}
{% if amneziawgVersion %}
<div class="text-muted" style="margin-top: 1em; margin-bottom: 1em;"><small>{{ lang._('AmneziaWG plugin') }} {{ amneziawgVersion|e }}</small></div>
{% endif %}
{{ partial("layout_partials/base_dialog",['fields':formDialogEditAmneziaWGClient,'id':formGridAmneziaWGClient['edit_dialog_id'],'label':lang._('Edit peer')])}}
{{ partial("layout_partials/base_dialog",['fields':formDialogEditAmneziaWGServer,'id':formGridAmneziaWGServer['edit_dialog_id'],'label':lang._('Edit instance')])}}
