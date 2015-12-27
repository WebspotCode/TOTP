<?php

namespace spec\Spot\TOTP;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Spot\TOTP\TOTP;

/** @mixin  TOTP */
class TOTPSpec extends ObjectBehavior
{
    public function it_isInitializable()
    {
        $this->shouldHaveType(TOTP::class);
    }

    public function it_canCreateSecrets()
    {
        $this->createSecret()->shouldMatch('/^[ABCDEFGHIJKLMNOPQRSTUVWXYZ234567]{16}$/');
        $this->createSecret(8)->shouldMatch('/^[ABCDEFGHIJKLMNOPQRSTUVWXYZ234567]{8}$/');
        $this->createSecret(25)->shouldMatch('/^[ABCDEFGHIJKLMNOPQRSTUVWXYZ234567]{25}$/');
    }

    public function it_canCreateCodes()
    {
        $secret = 'ZPFBICX7L4OGVG6Q';
        $this->getCode($secret)->shouldMatch('/^[0-9]{6}$/');
        $this->getCode($secret, 8)->shouldReturn('573075');
        $this->getCode($secret, 300)->shouldReturn('338200');
        $this->getCode($secret, 666)->shouldReturn('978351');
        $this->getCode($secret, 999999)->shouldReturn('526629');
    }

    public function it_canCreateQRCodeUrl()
    {
        $name = 'me@myself.dev';
        $secret = 'ZPFBICX7L4OGVG6Q';
        $title = 'X-wing';
        $this->getQRCodeUrl($name, $secret)
            ->shouldReturn('otpauth://totp/me%40myself.dev?secret=ZPFBICX7L4OGVG6Q');
        $this->getQRCodeUrl($name, $secret, $title)
            ->shouldReturn('otpauth://totp/me%40myself.dev?secret=ZPFBICX7L4OGVG6Q&issuer=X-wing');
    }

    public function it_canVerifyCodes()
    {
        $secret = 'ZPFBICX7L4OGVG6Q';

        $this->verifyCode($secret, '573075', 0, 8)->shouldReturn(true);
        $this->verifyCode($secret, '573075', 0, 7)->shouldReturn(false);

        $this->verifyCode($secret, '338200', 2, 302)->shouldReturn(true);
        $this->verifyCode($secret, '338200', 2, 303)->shouldReturn(false);
        $this->verifyCode($secret, '338200', 2, 298)->shouldReturn(true);
        $this->verifyCode($secret, '338200', 2, 297)->shouldReturn(false);

        $this->shouldThrow(\InvalidArgumentException::class)->duringVerifyCode($secret, '123');
    }
}
