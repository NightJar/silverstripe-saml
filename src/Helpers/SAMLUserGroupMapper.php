<?php

namespace SilverStripe\SAML\Helpers;

use OneLogin\Saml2\Auth;
use UnexpectedValueException;
use SilverStripe\Core\Extensible;
use Psr\Log\LoggerInterface;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\DataObject;
use SilverStripe\SAML\Services\SAMLConfiguration;
use SilverStripe\Security\Group;
use SilverStripe\Security\Member;

class SAMLUserGroupMapper
{
    use Injectable;
    use Configurable;
    use Extensible;

    /**
     * Group claims field URL defined on IdP
     * This is the `Name` attribute of the `saml:Attribute` element that will contain `saml:AttibuteValue`s listing IdP
     * group identifiers
     *
     * @var string
     * @config
     */
    private static string $group_claims_field = '';

    /**
     * Group DataObject field name used to identify a group to sync/map onto
     *
     * @var string
     * @config
     */
    private static string $group_object_field = 'Title';

    /**
     * Defines the mapping between the group defined on IdP and the CMS.
     *
     * A mapping of IdP group identifier (of some form - GUID/UUID/ObjectId, Title, etc.) => Silverstripe Group Title
     *
     * Note: Groups should be defined on both `group_map` config and IdP before a member can be added. If a group is
     * defined only by the IdP, the group will not be created; thus the member not assigned to it, even if it exists via
     * manual creation by an Administrator with an identical name to a group in the IdP.
     *
     * @var array IdP group identifier => Silverstripe `Group` identifier
     * @config
     */
    private static array $group_map = [];

    /**
     * Whether to create Silverstripe CMS groups present in the map, but not in the database
     *
     * @var bool
     * @config
     */
    private static bool $create_missing_groups = true;

    /**
     * Allows members to persistently belong to a manually-created group which does not exist on IdP
     * I.e. groups that are not listed in the `group_map` config setting for this class.
     *
     * The behaviour _when false_ is to reset assignments and assign *only* those identified both by the IdP AND listed
     * in the `group_map` setting when starting a new authenticated session (log in).
     *
     * @var bool
     * @config
     */
    private static bool $allow_manual_group = true;

    /**
     * By default a warning log will be created when the IdP supplies a group identifier that is not present in the
     * {@see group_map} configuration. If the IdP cannot be configured to restrict groups added to the claim, this could
     * be rather annoying, so it can be optionally disabled.
     *
     * @var bool
     * @config
     */
    private static bool $suppress_unknown_group_warning = false;

    /**
     * A convenience configuration value for mono-lingual sites to avoid creating language files in order to configure
     * a bit of static text. Default unset (null) to use the hard-coded translation default instead.
     *
     * This is used in creating group titles.
     * Only used when `crate_missing_groups` is true AND `group_object_field` is NOT "Title".
     * When `group_object_field` IS "Title", the value here is overwritten anyway (with the AttributeValue of the claim)
     *
     * This value is useful in cases when e.g. `group_object_field` is set to "Code", and the IdP AttributeValue is a
     * GUID, which is also being used as the value for `Code` as it makes cross referencing easier.
     * E.g. a group_map of [12345678-90ab-cdef-fedc-ba0987654321 => 12345678-90ab-cdef-fedc-ba0987654321]
     * The title for a new group would then be "IdP group: 12345678-90ab-cdef-fedc-ba0987654321"
     * as it would otherwise be blank - which is extremely unhelpful for CMS admins.
     *
     * @var string|null
     * @config
     */
    private static ?string $default_group_title_prefix = null;

    /**
     * Check if group claims field is set and assigns member to configured groups
     *
     * @param Auth $auth
     * @param Member $member
     * @param string $errorId
     * @return Member
     * @throws UnexpectedValueException
     */
    public function map(Auth $auth, Member $member, string $errorId): Member
    {
        $config = $this->config();
        $logger = Injector::inst()->get(LoggerInterface::class);
        $groupClaimsField = $config->get('group_claims_field') ?? '';
        $groupIdentifyingField = $config->get('group_object_field') ?? 'Title';
        $groupMap = $config->get('group_map') ?? [];
        $groupTitles = array_values($groupMap);

        // Ensure Group field is valid
        if (!isset(Group::getSchema()->databaseFields(Group::class)[$groupIdentifyingField])) {
            throw new UnexpectedValueException(sprintf(
                'The value of the %s.group_object_field configuration value must be a valid database field on %s.'
                . ' If "%s" is your expected value, perhaps you\'ve neglected to apply an Extension to %s?',
                self::class,
                Group::class,
                $groupIdentifyingField,
                Group::class
            ));
        }

        // Check if group mapping config exists
        if (empty($groupMap) || empty($groupClaimsField)) {
            $logger->error("[$errorId] Member group assignment is enabled, but the mapping configuration is missing");
            return $member;
        }

        // Identify and deal with groups that don't exist (per configuration; either notify or create)
        $existingGroups = Group::get()
            ->filter($groupIdentifyingField, $groupTitles)
            ->column($groupIdentifyingField);
        $missingGroups = array_diff($groupTitles, $existingGroups);
        if ($config->get('create_missing_groups')) {
            $defaultTitlePrefix = _t(
                self::class . '.DEFAULT_GROUP_TITLE_PREFIX',
                $config->get('default_group_title_prefix') ?? 'IdP group:'
            );
            foreach ($missingGroups as $missingGroup) {
                Group::create()
                    ->update(['Title' => trim("$defaultTitlePrefix $missingGroup")])
                    ->update([$groupIdentifyingField => $missingGroup]) // overwrites Title if group id field is "Title"
                    ->write();
            }
        } elseif (count($missingGroups)) {
            $logger->warn("[$errorId] Groups in mapping configuration do not exist, so cannot be assigned");
        }

        // Ensure members are not in groups they shouldn't be. Membership is reset for ALL groups, unless
        // `allow_manual_group` is true, then only IdP synced groups are removed (as defined by `group_map`).
        $memberGroups = $member->Groups();
        if ((bool)$config->get('allow_manual_group')) {
            $memberGroups = $memberGroups->filter($groupIdentifyingField, $groupTitles);
        }
        $memberGroups->removeAll();

        // Get groups from SAML response
        $claimedGroups = $auth->getAttribute($groupClaimsField);

        $this->extend('onBeforeGroupAssignment', $claimedGroups);

        if (is_null($claimedGroups)) {
            $logger->error("[$errorId] Group claim info missing from SAML response");
            return $member;
        }
        if (!is_array($claimedGroups)) {
            $logger->error("[$errorId] Group claim info from SAML response in unexpected format");
            return $member;
        }

        $configuredGroups = array_keys($groupMap);
        $invalidGroups = array_diff($claimedGroups, $configuredGroups);
        if (!empty($invalidGroups) && !$config->get('suppress_unknown_group_warning')) {
            $logger->warning(
                "[$errorId] SAML response contains unknown groups (perhaps they need adding to the `group_map`?): "
                . implode(', ', $invalidGroups)
            );
        }

        $assignedGroups = array_values(array_intersect_key($groupMap, array_flip($claimedGroups)));
        foreach (Group::get()->filter($groupIdentifyingField, $assignedGroups) as $group) {
            $group->DirectMembers()->add($member);
        }

        return $member;
    }
}
