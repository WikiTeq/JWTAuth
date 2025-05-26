<?php
namespace MediaWiki\Extension\JWTAuth\Models;

use MediaWiki\Extension\JWTAuth\JWTAuth;
use MediaWiki\Extension\JWTAuth\Models\JWTResponse;
use MediaWiki\MediaWikiServices;
use MediaWiki\Session\Session;
use MediaWiki\User\UserGroupManager;
use Psr\Log\LoggerInterface;
use User;
use Wikimedia\Timestamp\ConvertibleTimestamp;

class ProposedUser {
    private User $proposedUser;

    private LoggerInterface $logger;

    private function __construct(
        User $proposedUser,
        LoggerInterface $logger
    ) {
        $this->proposedUser = $proposedUser;
        $this->logger = $logger;
    }

    public static function makeUserFromJWTResponse(
        JWTResponse $jwtResponse,
        UserGroupManager $userGroupManager,
        LoggerInterface $logger
    ): ProposedUser {
        $username = $jwtResponse->getUsername();
        $email = $jwtResponse->getEmailAddress();
        $realname = $jwtResponse->getFullName();

		$proposedUser = User::newFromName( $username, 'usable' );
		$logger->debug("Default user proposal is " . $proposedUser->getName());

		// Allow 3rd parties to alter the proposed user
		$logger->debug("Offering extensions to override proposed user.");
		MediaWikiServices::getInstance()->getHookContainer()->run(
			'JWTAuthProposeUser',
			[
				&$proposedUser,
				$jwtResponse
			]
		);
		$logger->debug("Proposed user after extension hook is " . $proposedUser->getName());

		// If either some extension found a user for us
        if ( $proposedUser !== false && $proposedUser->getId() != 0 ) {
            $logger->debug("$username does exist with an ID " . $proposedUser->getId());
            $proposedUser->mId = $proposedUser->getId();
            $proposedUser->loadFromId();
			MediaWikiServices::getInstance()->getHookContainer()->run(
				'JWTAuthUserFound',
				[
					$proposedUser,
					$jwtResponse
				]
			);
        } else {
            // TODO: use autoCreateUser in https://gerrit.wikimedia.org/g/mediawiki/core/+/64c6ce7b95188ad381ee947b726fadde6aafe1c1/includes/auth/AuthManager.php
            $logger->debug("$username does not exist; attempting to creating user");
            $proposedUser->loadDefaults($username);
            $proposedUser->mName = $username;
            if ($realname !== null) {
                $proposedUser->setRealName($realname);
            }
            $proposedUser->mEmail = $email;
            $now = ConvertibleTimestamp::now(TS_UNIX);
            $proposedUser->mEmailAuthenticated = $now;
            $proposedUser->mTouched = $now;
            $proposedUser->addToDatabase();
			MediaWikiServices::getInstance()->getHookContainer()->run(
				'JWTAuthUserCreated',
				[
					$proposedUser,
					$jwtResponse
				]
			);
        }

        $groupsToBeAdded = $jwtResponse->getGroups();
        $logger->debug("Add groups: " . print_r($groupsToBeAdded, true));
        foreach ($groupsToBeAdded as $group) {
            $userGroupManager->addUserToGroup($proposedUser, $group);
        }
        $groupsToBeRemoved = $jwtResponse->getGroupsToRemove();
        foreach ($groupsToBeRemoved as $group) {
            $userGroupManager->removeUserFromGroup($proposedUser, $group);
        }

        $logger->debug("Proposed user formed and ready: " . print_r($proposedUser, true));

        $proposedUserObject = new ProposedUser(
            $proposedUser,
            $logger
        );

        return $proposedUserObject;
    }

    public function setUserInSession(
        Session $globalSession
    ): void {
        // Need to persist the session.
        $globalSession->persist();

        $this->logger->debug("Global session acquired.");

        $globalSession->setUser($this->proposedUser);

        $this->logger->debug("Set user in global session.");
        $this->logger->debug("The user in global session is now: " . print_r($globalSession->getUser(), true));
    }

	public function getProposedUser() : User {
		return $this->proposedUser;
	}
}
