#!/usr/bin/perl -w

    use CPANPLUS;
    use strict;
#   use warnings;

    CPANPLUS::Backend->new( conf => { prereqs => 1 } )->install(
        modules => [ qw(
				Crypt::Camellia
				Crypt::Camellia_PP
				RPC::XML
				RPC::XML::Client
				LWP::Protocol::https
				LWP::Protocol::socks
				XML::FeedPP
				Net::Twitter::Lite::WithAPIv1_1			
        ) ]
    );

