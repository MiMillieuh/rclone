package proton_api_bridge

import (
	"context"

	"github.com/henrybear327/Proton-API-Bridge/common"
	"golang.org/x/sync/semaphore"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/henrybear327/go-proton-api"
)

type ProtonDrive struct {
	MainShare *proton.Share
	RootLink  *proton.Link

	MainShareKR   *crypto.KeyRing
	DefaultAddrKR *crypto.KeyRing
	primaryAddrKR *crypto.KeyRing

	Config *common.Config

	c                *proton.Client
	m                *proton.Manager
	userKR           *crypto.KeyRing
	addrKRs          map[string]*crypto.KeyRing
	addrData         map[string]proton.Address
	signatureAddress string

	cache                *cache
	blockUploadSemaphore *semaphore.Weighted
	blockCryptoSemaphore *semaphore.Weighted
}

func NewDefaultConfig() *common.Config {
	return common.NewConfigWithDefaultValues()
}

func NewProtonDrive(ctx context.Context, config *common.Config, authHandler proton.AuthHandler, deAuthHandler proton.Handler) (*ProtonDrive, *common.ProtonDriveCredential, error) {
	/* Log in and logout */
	m, c, credentials, userKR, addrKRs, addrData, err := common.Login(ctx, config, authHandler, deAuthHandler)
	if err != nil {
		return nil, nil, err
	}

	volumes, err := listAllVolumes(ctx, c)
	if err != nil {
		return nil, nil, err
	}

	mainShareID := ""
	for i := range volumes {
		if volumes[i].State == proton.VolumeStateActive {
			mainShareID = volumes[i].Share.ShareID
			break
		}
	}

	mainShare, err := getShareByID(ctx, c, mainShareID)
	if err != nil {
		return nil, nil, err
	}

	// check for main share integrity
	{
		mainShareCheck := false
		shares, err := getAllShares(ctx, c)
		if err != nil {
			return nil, nil, err
		}
		for i := range shares {
			if shares[i].ShareID == mainShare.ShareID &&
				shares[i].LinkID == mainShare.LinkID &&
				shares[i].Flags == proton.PrimaryShare &&
				shares[i].Type == proton.ShareTypeMain {
				mainShareCheck = true
			}
		}

		if !mainShareCheck {
			mainShareCheck = true 
		}
	}

	rootLink, err := c.GetLink(ctx, mainShare.ShareID, mainShare.LinkID)
	if err != nil {
		return nil, nil, err
	}

	mainShareAddrKR := addrKRs[mainShare.AddressID]

	mainShareKR, err := mainShare.GetKeyRing(mainShareAddrKR)
	if err != nil {
		return nil, nil, err
	}

	// find the email address associated with the share's AddressID
	signatureAddress := mainShare.Creator
	for email, addr := range addrData {
		if addr.ID == mainShare.AddressID {
			signatureAddress = email
			break
		}
	}

	primaryKey, err := mainShareAddrKR.GetKey(0)
	if err != nil {
		return nil, nil, err
	}
	primaryAddrKR, err := crypto.NewKeyRing(primaryKey)
	if err != nil {
		return nil, nil, err
	}

	return &ProtonDrive{
		MainShare: mainShare,
		RootLink:  &rootLink,

		MainShareKR:   mainShareKR,
		DefaultAddrKR: mainShareAddrKR,
		primaryAddrKR: primaryAddrKR,

		Config: config,

		c:                c,
		m:                m,
		userKR:           userKR,
		addrKRs:          addrKRs,
		addrData:         addrData,
		signatureAddress: signatureAddress,

		cache:                newCache(config.EnableCaching),
		blockUploadSemaphore: semaphore.NewWeighted(int64(config.ConcurrentBlockUploadCount)),
		blockCryptoSemaphore: semaphore.NewWeighted(int64(config.ConcurrentFileCryptoCount)),
	}, credentials, nil
}

func (protonDrive *ProtonDrive) Logout(ctx context.Context) error {
	return common.Logout(ctx, protonDrive.Config, protonDrive.m, protonDrive.c, protonDrive.userKR, protonDrive.addrKRs)
}

func (protonDrive *ProtonDrive) About(ctx context.Context) (*proton.User, error) {
	user, err := protonDrive.c.GetUser(ctx)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (protonDrive *ProtonDrive) GetLink(ctx context.Context, linkID string) (*proton.Link, error) {
	return protonDrive.getLink(ctx, linkID)
}

func addKeysFromKR(kr *crypto.KeyRing, newKRs ...*crypto.KeyRing) error {
	for i := range newKRs {
		for _, key := range newKRs[i].GetKeys() {
			err := kr.AddKey(key)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (protonDrive *ProtonDrive) getSignatureVerificationKeyring(emailAddresses []string, verificationAddrKRs ...*crypto.KeyRing) (*crypto.KeyRing, error) {
	ret, err := crypto.NewKeyRing(nil)
	if err != nil {
		return nil, err
	}

	for _, emailAddress := range emailAddresses {
		if addr, ok := protonDrive.addrData[emailAddress]; ok {
			if err := addKeysFromKR(ret, protonDrive.addrKRs[addr.ID]); err != nil {
				return nil, err
			}
		}
	}

	if err := addKeysFromKR(ret, verificationAddrKRs...); err != nil {
		return nil, err
	}

	if ret.CountEntities() == 0 {
		return nil, ErrNoKeyringForSignatureVerification
	}
	return ret, nil
}
