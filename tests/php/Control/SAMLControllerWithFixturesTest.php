<?php

namespace SilverStripe\SAML\Tests\Control;

use OneLogin\Saml2\Auth;
use Psr\Log\LoggerInterface;
use ReflectionClass;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\Session;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\SAML\Control\SAMLController;
use SilverStripe\SAML\Helpers\SAMLHelper;
use SilverStripe\SAML\Model\SAMLResponse;
use SilverStripe\SAML\Services\SAMLConfiguration;
use SilverStripe\Security\Member;

class SAMLControllerWithFixturesTest extends SapphireTest
{
    const DEFAULT_CLAIMS = [
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname' => 'FirstName',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname' => 'Surname',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress' => 'Email',
    ];

    const DEFAULT_CONFIG = [
        'expect_binary_nameid' => true,
        'validate_nameid_as_guid' => true,
        'expose_guid_as_attribute' => false,
        'allow_insecure_email_linking' => false,
        'login_persistent' => false,
    ];

    const DEFAULT_GUID = '12345678-1234-asdf-0987-12345678asdf';

    const DEFAULT_RETURNS = [
        'binToStrGuid' => self::DEFAULT_GUID,
        'validGuid' => true,
        'processResponse' => null, // string|null throws Exception when string
        'getLastErrorReason' => null, // string|null
        'isAuthenticated' => true,
        'getNameId' => self::DEFAULT_GUID,
        'getAttributes' => [
            'FirstName' => 'Test',
            'Surname' => 'User',
            'Email' => 'test@test.test',
        ],
    ];

    protected static $fixture_file = 'membersAndResponses.yml';

    public function testReplayAttack()
    {
        $auth = $this->createStub(Auth::class);
        $auth->method('getLastMessageId')->willReturn('used');
        $auth->method('getLastAssertionNotOnOrAfter')->willReturn('2024-11-01 15:07:33');

        $request = $this->createStub(HTTPRequest::class);
        $request->method('getIP')->willReturn('000.123.456.789');

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())->method('error')->with(
            '[uerr] SAML replay attack detected!'
            . ' Response ID "used", expires "2024-11-01 15:07:33", client IP "000.123.456.789"'
        );
        Injector::inst()->registerService($logger, LoggerInterface::class);

        $controller = new SAMLController();
        $controller->setRequest($request);
        $reflection = new ReflectionClass(SAMLController::class);
        $method = $reflection->getMethod('checkForReplayAttack');

        $result = $method->invokeArgs($controller, [$auth, 'uerr']);

        $this->assertTrue($result);
        $this->assertCount(1, SAMLResponse::get()->filter('ResponseID', 'used'));
    }

    public function testReplayCheck()
    {
        $auth = $this->createStub(Auth::class);
        $auth->method('getLastMessageId')->willReturn('current');
        $auth->method('getLastAssertionNotOnOrAfter')->willReturn('2024-11-01 15:07:33');

        $controller = new SAMLController();
        $reflection = new ReflectionClass(SAMLController::class);
        $method = $reflection->getMethod('checkForReplayAttack');

        $result = $method->invokeArgs($controller, [$auth]);

        $this->assertFalse($result);
        $this->assertCount(1, SAMLResponse::get()->filter('ResponseID', 'current'));
    }

    private function configureACS(array $claims = [], array $config = [], array $returns = []): SAMLController
    {
        $claims = array_merge(self::DEFAULT_CLAIMS, $claims);
        $returns = array_merge(self::DEFAULT_RETURNS, $returns);
        Director::config()->set('alternate_base_url', 'https://running.test');
        $samlConfigConfig = SAMLConfiguration::config();
        foreach (array_merge(self::DEFAULT_CONFIG, $config) as $key => $value) {
            $samlConfigConfig->set($key, $value);
        }
        Member::config()->set('claims_field_mappings', self::DEFAULT_CLAIMS);

        $helper = $this->createStub(SAMLHelper::class);
        $auth = $this->createStub(Auth::class);
        $request = $this->createStub(HTTPRequest::class);
        $session = $this->createStub(Session::class);
        $logger = $this->createMock(LoggerInterface::class);
        $helper->method('getSAMLAuth')->willReturn($auth);

        $helper->method('binToStrGuid')->willReturn($returns['binToStrGuid']);
        $helper->method('validGuid')->willReturn($returns['validGuid']);
        $auth->method('getLastErrorReason')->willReturn($returns['getLastErrorReason']);
        $auth->method('isAuthenticated')->willReturn($returns['isAuthenticated']);
        $auth->method('getNameId')->willReturn($returns['getNameId']);
        $auth->method('getAttributes')->willReturn(
            array_combine(array_keys($claims), array_map(fn($name) => [$returns['getAttributes'][$name]], $claims))
        );
        if (is_string($returns['processResponse'])) {
            $auth->method('processResponse')->willThrowException(new Exception($returns['processResponse']));
        }

        $auth->method('getSessionIndex')->willReturn('anSesh');
        $request->method('getSession')->willReturn($session);
        $session->method('get')->with('BackURL')->willReturn('/another/page');
        Injector::inst()->registerService($helper, SAMLHelper::class);
        Injector::inst()->registerService($logger, LoggerInterface::class);


        $controller = new SAMLController();
        $controller->setRequest($request);

        return $controller;
    }

    public function testACSHappyPath()
    {
        $this->assertCount(0, Member::get()->filter('GUID', self::DEFAULT_GUID));

        $controller = $this->configureACS();
        $controller->getLogger()->expects($this->never())->method($this->anything());
        $response = $controller->acs();

        $this->assertInstanceOf(HTTPResponse::class, $response);
        $this->assertSame(302, $response->getStatusCode());
        $this->assertSame('https://running.test/another/page', $response->getHeader('location'));
        $members = Member::get()->filter('GUID', self::DEFAULT_GUID);
        $this->assertCount(1, $members);
        $member = $members->first();
        $this->assertSame('Test', $member->FirstName);
        $this->assertSame('User', $member->Surname);
        $this->assertSame('test@test.test', $member->Email);
    }
}
