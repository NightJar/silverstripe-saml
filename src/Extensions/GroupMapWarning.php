<?php

namespace SilverStripe\SAML\Extensions;

use SilverStripe\Core\Extension;
use SilverStripe\SAML\Helpers\SAMLUserGroupMapper;
use SilverStripe\SAML\Services\SAMLConfiguration;

class GroupMapWarning extends Extension
{
    public function updateCMSFields($fields)
    {
        // Some coupling going on here. But it's via config... so not so bad?
        if (!SAMLConfiguration::config()->get('map_user_group')) {
            return;
        }
        $mapperConfig = SAMLUserGroupMapper::config();
        $mapFieldName = $mapperConfig->get('group_object_field') ?? '';
        if (!$mapFieldName) {
            return;
        }
        $mappedField = $fields->dataFieldByName($mapFieldName);
        if (!$mappedField) {
            return;
        }
        $relevantObject = in_array($this->owner->$mapFieldName, $mapperConfig->get('group_map') ?? []);
        if ($relevantObject && !($mappedField->isReadOnly() || $mappedField->isDisabled())) {
            $mappedField->setRightTitle(_t(
                self::class . '.CHANGE_WARNING',
                "Changing '{label}' may cause permission issues for members using single sign on (SSO)",
                ['label' => $mappedField->Title()]
            ));
        }
    }
}
