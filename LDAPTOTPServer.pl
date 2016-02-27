#!/usr/bin/perl
use strict;
use warnings;
use IO::Select;
use IO::Socket;
use LDAPTOTPServer qw ();
use POSIX qw(setsid);
use Getopt::Std;


my %cmd_options=();
getopts('p:t:D:d:c:l',\%cmd_options);

my $file="";
my $tmp_dir="";

$SIG{'PIPE'} ='IGNORE';
my $debug=0;

if(exists($cmd_options{'d'})){
    $debug=1;
}

if(exists($cmd_options{'c'})){
    print "Please enter auth dn: ";my $dn=<>;chomp($dn);
    print "Please enter user name: ";my $user=<>;chomp($user);
    print "Please enter password: ";my $pass1=<>;chomp($pass1);
    print "Please enter password AGAIN: ";my $pass2=<>;chomp($pass2);

    if(($pass1 ne $pass2)||($pass1 eq "")){
        print "Error the two passwords do not match or are empty!\n";
        exit 1;
    }
    print "How many digits for the TOTP (6-10): ";my $totp_digits=<>;chomp($totp_digits);

    my $ls=LDAPTOTPServer->new($debug,$file,$tmp_dir,$debug);

    my $salt=unpack "H*", $ls->getRandom(10);
    my $pass_hash=$ls->getHash($pass1,$salt);
    my $totp_secret=$ls->generateBase32Secret();

    print "Copy the following line manually to $file\n";
    print "$dn:$user:$pass_hash:$salt:$totp_secret:$totp_digits\n";

}elsif(((keys %cmd_options)==0)||(!exists($cmd_options{'p'})||(!exists($cmd_options{'t'})))){
    print "$0 OPTION\n\n";
    print "Options:\n";
    print "\t-p file\n";
    print "\t\tpath to the file containing the passwords (mandatory)\n";
    print "\t-t dir\n";
    print "\t\tdirectory where temporarily session files are stored (mandatory)\n";
    print "\t-c\n";
    print "\t\tcreate a new password entry\n";
    print "\t-l ip\n";
    print "\t\twhich ip to bind to\n";
    print "\t-D\n";
    print "\t\trun as daemon\n";
    print "\t-d\n";
    print "\t\tdebug output\n";
}else{
    $file=$cmd_options{'p'};
    $tmp_dir=$cmd_options{'t'};
    if(exists($cmd_options{'D'})){
	if(fork()){
	    exit(0);
	}else{
	    setsid();
	    start_serving();
	}
    }else{
	start_serving();
    }
}
exit 0;

sub start_serving{
    my $l="127.0.0.1";
    if(exists($cmd_options{'l'})){
	$l=$cmd_options{'l'};
    }
    my $sock = IO::Socket::INET->new(
	Listen => 5,
	Proto => 'tcp',
	Reuse => 1,
	LocalAddr => $l,
	LocalPort => 389
    )||die("Could not create listening server");
    my $sel = IO::Select->new($sock);
    my %Handlers;
    while (my @ready = $sel->can_read) {
	foreach my $fh (@ready) {
	    if ($fh == $sock) {
		# let's create a new socket
		my $psock = $sock->accept;
		$sel->add($psock);
		$Handlers{*$psock} = LDAPTOTPServer->new($psock,$file,$tmp_dir,$debug);
	    } else {
		my $result = $Handlers{*$fh}->handle;
		if ($result) {
		    # we have finished with the socket
            	    $sel->remove($fh);
            	    $fh->close;
            	    delete $Handlers{*$fh};
		}
	    }
	}
    }
}
