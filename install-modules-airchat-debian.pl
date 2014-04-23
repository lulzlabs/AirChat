#!/usr/bin/perl -w

    use CPANPLUS;
    use strict;
#   use warnings;

    CPANPLUS::Backend->new( conf => { prereqs => 1 } )->install(
        modules => [ qw(
				Net::Twitter::Lite::WithAPIv1_1
				HTTP::Server::Simple::CGI::PreFork
				Crypt::Camellia
				Crypt::Camellia_PP
        ) ]
    );

