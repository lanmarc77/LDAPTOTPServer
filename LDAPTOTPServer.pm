package LDAPTOTPServer;
use strict;
use warnings;
use Data::Dumper;

use Digest::HMAC_SHA1 qw/ hmac_sha1_hex /;
use Digest::SHA3 qw(sha3_256_hex);
use Net::LDAP::Constant qw(LDAP_SUCCESS);
use Net::LDAP::Server();
use base 'Net::LDAP::Server';
#use fields qw();

my $session_timeout=300;#in seconds

my $tmp_dir="";
my $pwd_file="";
my $last_base="";
my $debug=0;

sub debug{
    if($debug){
	print localtime(time).": ".$_[0]."\n";
    }
}

use constant RESULT_OK => {
    'matchedDN' => '',
    'matchedUid' => '',
    'errorMessage' => '',
    'resultCode' => LDAP_SUCCESS
};

use constant RESULT_AUTH_ERROR => {
    'matchedDN' => '',
    'matchedUid' => '',
    'errorMessage' => '',
    'resultCode' => 49
};

# constructor
sub new {
    my $class = shift;
    my $self = $class->SUPER::new(@_);
    $pwd_file =$_[1];
    $tmp_dir =$_[2];
    $debug =$_[3];
    return $self;
}

# the bind operation
sub bind {
    my $self = shift;
    my $reqData = shift;
    debug("Bind...");
    if ($reqData->{'baseObject'}) {
        $last_base=$reqData->{'baseObject'};
    }
    debug(Dumper($reqData));
    if(defined($reqData->{'name'})){
        if(defined($reqData->{'authentication'})){
            if(defined($reqData->{'authentication'}{'simple'})){
                if(($reqData->{'name'} eq "")&&($reqData->{'authentication'}{'simple'} eq "")){
                    return RESULT_OK;
                }else{
                    my $req_user=$reqData->{'name'};
                    my $req_passtotp=$reqData->{'authentication'}{'simple'};
                    if($last_base ne ""){
                        cleanReqDB();
                        if(open(P,$pwd_file)){
                            foreach(<P>){
                                if($_ !~ /^\#/){
				    my $l=$_;chomp($l);
                                    my($base_dn,$user,$pass_hash,$salt,$totp_secret,$totp_digits,$session_timeout)=split(/\:/,$l);
				    if(defined(($totp_digits))){
					if($totp_digits !~ /\d+/){
					    $totp_digits=6;
					}
				    }else{
					$totp_digits=6;
				    }
				    if(defined(($session_timeout))){
					if($session_timeout !~ /\d+/){
					    $session_timeout=300;
					}
				    }else{
					$session_timeout=300;
				    }
                		    my $req_pass=substr($req_passtotp,0,length($req_passtotp)-$totp_digits);
                		    my $req_totp=substr($req_passtotp,length($req_passtotp)-$totp_digits,$totp_digits);
                                    if(defined($base_dn)&&($base_dn eq $last_base)&&($user eq $req_user)){
					if((defined($totp_secret)&&($totp_secret ne ""))){
					    debug("Password correct for $base_dn,$req_user");
                                    	    my $req_pass_hash=getHash($req_pass,$salt);
                                    	    if($req_pass_hash eq $pass_hash){
                                        	if($req_totp eq generateCurrentNumber($totp_secret,$totp_digits,30)){
						    debug("TOTP correct for $req_user");
                                            	    saveReqDB($req_totp.$base_dn.$user,$session_timeout);
                                            	    return RESULT_OK;
                                        	}else{
                                            	    if(checkReqDB($req_totp.$base_dn.$user,$session_timeout)){
							debug("TOTP cached auth for $base_dn,$req_user");
                                                	return RESULT_OK;
                                            	    }
						}
					    }
                                        }else{
                                    	    my $req_pass_hash=getHash($req_passtotp,$salt);
                                    	    if($req_pass_hash eq $pass_hash){
						debug("Password as single auth factor correct for $base_dn,$req_user");
                                    	        return RESULT_OK;
					    }
					}
                                    }
                                }
                            }
                        }
                    }
		    debug("User denied");
                    return RESULT_AUTH_ERROR;
                }
            }
        }else{
	    debug("User denied");
            return RESULT_AUTH_ERROR;
        }
    }else{
	debug("User denied");
        return RESULT_AUTH_ERROR;
    }
    return RESULT_OK;
}

# the search operation
sub search {
    my $self = shift;
    my $reqData = shift;
    debug("Searching...");
    if ($reqData->{'baseObject'}) {
        $last_base=$reqData->{'baseObject'};
    }
    debug(Dumper($reqData));
    my $base = $reqData->{'baseObject'};

    my @entries;
    my $entry = Net::LDAP::Entry->new;


    if(defined($reqData->{'filter'})){
        if(defined($reqData->{'filter'}{'and'})){
            foreach(@{$reqData->{'filter'}{'and'}}){
                if(defined($_->{'equalityMatch'})){
                    if(defined($_->{'equalityMatch'}{'attributeDesc'})){
                        if(($_->{'equalityMatch'}{'attributeDesc'}) eq "uid"){
                            $entry->dn($_->{'equalityMatch'}{'assertionValue'});
                            $entry->add(
                                'matchedUid' => $_->{'equalityMatch'}{'assertionValue'},
                                'matchedDN' => $_->{'equalityMatch'}{'assertionValue'},
                            );
                        }
                    }
                }
            }
        }
        if(defined($reqData->{'filter'}{'equalityMatch'})){
            if(defined($reqData->{'filter'}{'equalityMatch'}{'attributeDesc'})){
                if(($reqData->{'filter'}{'equalityMatch'}{'attributeDesc'}) eq "uid"){
                    $entry->dn($reqData->{'filter'}{'equalityMatch'}{'assertionValue'});
                    $entry->add(
                        'matchedUid' => $reqData->{'filter'}{'equalityMatch'}{'assertionValue'},
                        'matchedDN' => $reqData->{'filter'}{'equalityMatch'}{'assertionValue'},
                    )
                }
            }
        }
    }
    push @entries, $entry;
    return RESULT_OK, @entries;
}

sub cleanReqDB{
    if(opendir(DIR,$tmp_dir)){
        while(readdir(DIR)){
            if(($_ ne ".")&&($_ ne "..")){
                my $epoch_timestamp = (stat($tmp_dir."/".$_))[9];
                if((time-$epoch_timestamp)>0){
                    unlink($tmp_dir."/".$_);
                }
            }
        }
    }
}

sub saveReqDB{
    my $id=$_[0];
    my $session_timeout=$_[1];
    mkdir ($tmp_dir,0700);
    my $f=$tmp_dir."/".sha3_256_hex($id);
    open(F,">".$f);
    close(F);
    utime time(),time()+$session_timeout,$f;
}

sub checkReqDB{
    my $id=$_[0];
    my $session_timeout=$_[1];
    my $hash=sha3_256_hex($id);
    if(-e $tmp_dir."/".$hash){
	my $epoch_timestamp = (stat($tmp_dir."/".$hash))[9];
	if((time-$epoch_timestamp)<0){
	    utime time(),time()+$session_timeout,$tmp_dir."/".$hash;
    	    return 1;
	}
    }
    return 0;
}

sub isatty() { return open(my $tty, '+<', '/dev/tty'); }

sub getHash{
    my $pass=$_[0];
    my $salt=$_[1];
    if(ref($pass)){
	$pass=$_[1];
	$salt=$_[2];
    }
    return sha3_256_hex($pass.$salt)
}

#
# Generate a secret key in base32 format (A-Z2-7)
#
sub generateBase32Secret {
    my @chars = ("A".."Z", "2".."7");
    my $length = scalar(@chars);
    my $base32Secret = "";
    for (my $i = 0; $i < 16; $i++) {
        $base32Secret .= $chars[ord(getRandom(1))%$length];
    }
    return $base32Secret;
}

sub getRandom{
    my $b=$_[0];
    #my $b=shift;
    if(ref($b)){
	$b=$_[1];
    }
    if(open(R,"/dev/urandom")){
        my $r=0;
        if((sysread R,$r,$b)){
            if(length($r)>=$b){
                close(R);
                return $r;
            }else{
                die("Could not read enough data from/dev/urandom!");
            }
        }else{
            die("Could not read from/dev/urandom!");
        }
    }else{
        die("Could not open /dev/urandom!");
    }

}

# the rest of the operations will return an "unwilling to perform"

#
# Return the current number associated with base32 secret to be compared with user input.
#
sub generateCurrentNumber {
    my ($base32Secret) = $_[0];
    my ($digits) = $_[1];
    my ($time_step) = $_[2];

    # For more details of this magic algorithm, see:
    # http://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm

    # need a 16 character hex value
    my $paddedTime = sprintf("%016x", int(time() / $time_step));
    # this starts with \0's
    my $data = pack('H*', $paddedTime);
    my $key = decodeBase32($base32Secret);

    # encrypt the data with the key and return the SHA1 of it in hex
    my $hmac = hmac_sha1_hex($data, $key);

    # take the 4 least significant bits (1 hex char) from the encrypted string as an offset
    my $offset = hex(substr($hmac, -1));
    # take the 4 bytes (8 hex chars) at the offset (* 2 for hex), and drop the high bit
    my $encrypted = hex(substr($hmac, $offset * 2, 8)) & 0x7fffffff;

    my $div=10**$digits;
    # the token is then the last 6 digits in the number
    my $token = $encrypted % $div;
    # make sure it is 0 prefixed
    return sprintf("%0".$digits."d", $token);
}

#
# Decode a base32 number which is used to encode the secret.
#
sub decodeBase32 {
    my ($val) = @_;

    # turn into binary characters
    $val =~ tr|A-Z2-7|\0-\37|;
    # unpack into binary
    $val = unpack('B*', $val);

    # cut off the 000 prefix
    $val =~ s/000(.....)/$1/g;
    # trim off some characters if not 8 character aligned
    my $len = length($val);
    $val = substr($val, 0, $len & ~7) if $len & 7;

    # pack back up
    $val = pack('B*', $val);
    return $val;
}



1;
