#!/usr/bin/perl -w

    use CPANPLUS;
    use strict;
#   use warnings;

    CPANPLUS::Backend->new( conf => { prereqs => 1 } )->install(
        modules => [ qw(
				Digest::SHA 
				MIME::Base64
				Crypt::CBC
				Crypt::Rijndael
				Crypt::Camellia
				Crypt::Camellia_PP
				Compress::Zlib
				Crypt::OpenSSL::RSA
				RPC::XML
				RPC::XML::Client
				Data::Dumper
				Encode
				Net::SSLGlue::LWP
				LWP::UserAgent
				LWP::Protocol::https
				LWP::Protocol::socks
				JSON
				Net::Twitter::Lite::WithAPIv1_1
				XML::FeedPP
				HTTP::Server::Simple::CGI
				HTML::Entities
				base
				Time::HiRes 
        ) ]
    );

