package pf::Switch::Cisco::Cisco_WLC_IOS_XE;

=head1 NAME

pf::Switch::Cisco::Cisco_WLC_IOS_XE - Object oriented module to parse SNMP traps and 
manage Cisco Wireless Controllers Series running on Cisco IOS XE.

=head1 STATUS

This module is currently only a placeholder, see L<pf::Switch::Cisco::Cisco_WLC_AireOS> for relevant support items.

=cut

use strict;
use warnings;

use pf::util::wpa;
use pf::log;

use base ('pf::Switch::Cisco::Cisco_WLC_AireOS');

sub description { 'Cisco WLC (IOS XE)' }

sub find_user_by_psk {
    my ($self, $radius_request, $args) = @_;
    my $ssid = $self->getCiscoAvPairAttribute($radius_request,'cisco-wlan-ssid');
    my $cisco_bssid = $self->getCiscoAvPairAttribute($radius_request,'cisco-bssid');
    if ($cisco_bssid =~ /([0-9a-f]{2})[^0-9a-f]?([0-9a-f]{2})[^0-9a-f]?([0-9a-f]{2})[^0-9a-f]?([0-9a-f]{2})[^0-9a-f]?([0-9a-f]{2})[^0-9a-f]?([0-9a-f]{2})/i) {
        $cisco_bssid = $1.$2.$3.$4.$5.$6;
    }
    my $bssid = pack("H*", $cisco_bssid);
    my $username = pack("H*", $radius_request->{'User-Name'});
    my $anonce = $self->getCiscoAvPairAttribute($radius_request,'cisco-anonce');
    my $c8021x = $self->getCiscoAvPairAttribute($radius_request,'cisco-8021x-data');
    my $snonce = pf::util::wpa::snonce_from_eapol_key_frame($c8021x);
    my $eapol_key_frame = $c8021x;

    my $cache = $self->cache;
    if (exists $args->{'owner'} && $args->{'owner'}->{'pid'} ne "" && exists $args->{'owner'}->{'psk'} && defined $args->{'owner'}->{'psk'} && $args->{'owner'}->{'psk'} ne "") {
        if (check_if_radius_request_psk_matches($cache, $radius_request, $args->{'owner'}->{'psk'}, $ssid, $bssid, $username, $anonce, $snonce, $eapol_key_frame)) {
            get_logger->info("PSK matches the pid associated with the mac ".$args->{'owner'}->{'pid'});
            return $args->{'owner'}->{'pid'};
        }
    }

    my ($status, $iter) = pf::dal::person->search(
        -where => {
            psk => {'!=' => [-and => '', undef]},
        },
        -columns => [qw(pid psk)],
        -no_default_join => 1,
    );

    my $matched = 0;
    my $pid;
    # Try first the pid of the mac address
    while(my $person = $iter->next) {
        get_logger->warn("User ".$person->{pid}." has a PSK. Checking if it matches the one in the packet");
        if (check_if_radius_request_psk_matches($cache, $radius_request, $person->{'psk'}, $ssid, $bssid, $username, $anonce, $snonce, $eapol_key_frame)) {
            get_logger->info("PSK matches the one of ".$person->{pid});
            $pid = $person->{pid};
            last;
        }
    }
    return $pid;
}

sub check_if_radius_request_psk_matches {
    my ($cache, $radius_request, $psk, $ssid, $bssid, $username, $anonce, $snonce, $eapol_key_frame) = @_;

    my $pmk = $cache->compute(
        "Cisco_WLC_IOS_XE::check_if_radius_request_psk_matches::PMK::$ssid+$psk",
        {expires_in => '1 month', expires_variance => '.20'},
        sub { pf::util::wpa::calculate_pmk($ssid, $psk) },
    );

    return pf::util::wpa::match_mic(
      pf::util::wpa::calculate_ptk(
        $pmk,
        $bssid,
        $username,
        $anonce,
        $snonce,
      ),
      $eapol_key_frame,
    );
}

=head1 AUTHOR

Inverse inc. <info@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2005-2024 Inverse inc.

=head1 LICENSE

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
USA.

=cut

1;

# vim: set shiftwidth=4:
# vim: set expandtab:
# vim: set backspace=indent,eol,start:
