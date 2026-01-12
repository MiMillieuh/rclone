package proton_api_bridge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"mime"
	"os"
	"path/filepath"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/henrybear327/go-proton-api"
)

func (protonDrive *ProtonDrive) handleRevisionConflict(ctx context.Context, link *proton.Link, createFileResp *proton.CreateFileRes) (string, bool, error) {
	if link != nil {
		linkID := link.LinkID

		draftRevision, err := protonDrive.GetRevisions(ctx, link, proton.RevisionStateDraft)
		if err != nil {
			return "", false, err
		}

		if len(draftRevision) > 0 {
			if protonDrive.Config.ReplaceExistingDraft {
				if link.State == proton.LinkStateDraft {
					err = protonDrive.c.DeleteChildren(ctx, protonDrive.MainShare.ShareID, link.ParentLinkID, linkID)
					if err != nil {
						return "", false, err
					}
					return "", true, nil
				}
				err = protonDrive.c.DeleteRevision(ctx, protonDrive.MainShare.ShareID, linkID, draftRevision[0].ID)
				if err != nil {
					return "", false, err
				}
			} else {
				return "", false, ErrDraftExists
			}
		}

		newRevision, err := protonDrive.c.CreateRevision(ctx, protonDrive.MainShare.ShareID, linkID)
		if err != nil {
			return "", false, err
		}

		return newRevision.ID, false, nil
	} else if createFileResp != nil {
		return createFileResp.RevisionID, false, nil
	} else {
		return "", false, ErrInternalErrorOnFileUpload
	}
}

func (protonDrive *ProtonDrive) createFileUploadDraft(ctx context.Context, parentLink *proton.Link, filename string, modTime time.Time, mimeType string) (string, string, *crypto.SessionKey, *crypto.KeyRing, error) {
	parentNodeKR, err := protonDrive.getLinkKR(ctx, parentLink)
	if err != nil {
		return "", "", nil, nil, err
	}

	newNodeKey, newNodePassphraseEnc, newNodePassphraseSignature, err := generateNodeKeys(parentNodeKR, protonDrive.DefaultAddrKR)
	if err != nil {
		return "", "", nil, nil, err
	}

	createFileReq := proton.CreateFileReq{
		ParentLinkID: parentLink.LinkID,
		MIMEType:     mimeType,

		NodeKey:                 newNodeKey,
		NodePassphrase:          newNodePassphraseEnc,
		NodePassphraseSignature: newNodePassphraseSignature,

		SignatureAddress: protonDrive.signatureAddress,
	}

	err = createFileReq.SetName(filename, protonDrive.DefaultAddrKR, parentNodeKR)
	if err != nil {
		return "", "", nil, nil, err
	}

	signatureVerificationKR, err := protonDrive.getSignatureVerificationKeyring([]string{parentLink.SignatureEmail}, parentNodeKR)
	if err != nil {
		return "", "", nil, nil, err
	}
	parentHashKey, err := parentLink.GetHashKey(parentNodeKR, signatureVerificationKR)
	if err != nil {
		return "", "", nil, nil, err
	}

	err = createFileReq.SetHash(filename, parentHashKey)
	if err != nil {
		return "", "", nil, nil, err
	}

	newNodeKR, err := getKeyRing(parentNodeKR, protonDrive.DefaultAddrKR, newNodeKey, newNodePassphraseEnc, newNodePassphraseSignature)
	if err != nil {
		return "", "", nil, nil, err
	}

	newSessionKey, err := createFileReq.SetContentKeyPacketAndSignature(newNodeKR)
	if err != nil {
		return "", "", nil, nil, err
	}

	createFileAction := func() (*proton.CreateFileRes, *proton.Link, error) {
		createFileResp, err := protonDrive.c.CreateFile(ctx, protonDrive.MainShare.ShareID, createFileReq)
		if err != nil {
			if err != proton.ErrFileNameExist {
				return nil, nil, err
			}
			link, err := protonDrive.SearchByNameInActiveFolder(ctx, parentLink, filename, true, false, proton.LinkStateActive)
			if err != nil {
				return nil, nil, err
			}
			if link == nil {
				link, err = protonDrive.SearchByNameInActiveFolder(ctx, parentLink, filename, true, false, proton.LinkStateDraft)
				if err != nil {
					return nil, nil, err
				}
				if link == nil {
					return nil, nil, ErrCantLocateRevision
				}
			}
			return nil, link, nil
		}
		return &createFileResp, nil, nil
	}

	createFileResp, link, err := createFileAction()
	if err != nil {
		return "", "", nil, nil, err
	}

	revisionID, shouldSubmitCreateFileRequestAgain, err := protonDrive.handleRevisionConflict(ctx, link, createFileResp)
	if err != nil {
		return "", "", nil, nil, err
	}

	if shouldSubmitCreateFileRequestAgain {
		createFileResp, link, err = createFileAction()
		if err != nil {
			return "", "", nil, nil, err
		}
		revisionID, _, err = protonDrive.handleRevisionConflict(ctx, link, createFileResp)
		if err != nil {
			return "", "", nil, nil, err
		}
	}

	linkID := ""
	if link != nil {
		linkID = link.LinkID
		parentNodeKR, err = protonDrive.getLinkKRByID(ctx, link.ParentLinkID)
		if err != nil {
			return "", "", nil, nil, err
		}
		signatureVerificationKR, err := protonDrive.getSignatureVerificationKeyring([]string{link.SignatureEmail})
		if err != nil {
			return "", "", nil, nil, err
		}
		newNodeKR, err = link.GetKeyRing(parentNodeKR, signatureVerificationKR)
		if err != nil {
			return "", "", nil, nil, err
		}
		newSessionKey, err = link.GetSessionKey(newNodeKR)
		if err != nil {
			return "", "", nil, nil, err
		}
	} else {
		linkID = createFileResp.ID
	}

	return linkID, revisionID, newSessionKey, newNodeKR, nil
}

func (protonDrive *ProtonDrive) uploadAndCollectBlockData(ctx context.Context, newSessionKey *crypto.SessionKey, newNodeKR *crypto.KeyRing, file io.Reader, linkID, revisionID string) ([]byte, int64, []int64, string, error) {
	type PendingUploadBlocks struct {
		blockUploadInfo proton.BlockUploadInfo
		encData         []byte
	}

	if newSessionKey == nil || newNodeKR == nil {
		return nil, 0, nil, "", ErrMissingInputUploadAndCollectBlockData
	}

	// Get verification data
	vDataRes, err := protonDrive.c.GetVerificationData(ctx, protonDrive.MainShare.ShareID, linkID, revisionID)
	if err != nil {
		return nil, 0, nil, "", err
	}
	vCode, err := base64.StdEncoding.DecodeString(vDataRes.VerificationCode)
	if err != nil {
		return nil, 0, nil, "", err
	}

	totalFileSize := int64(0)
	pendingUploadBlocks := make([]PendingUploadBlocks, 0)
	manifestSignatureData := make([]byte, 0)

	uploadPendingBlocks := func() error {
		if len(pendingUploadBlocks) == 0 {
			return nil
		}
		blockList := make([]proton.BlockUploadInfo, 0)
		for i := range pendingUploadBlocks {
			blockList = append(blockList, pendingUploadBlocks[i].blockUploadInfo)
		}
		blockUploadReq := proton.BlockUploadReq{
			AddressID:  protonDrive.MainShare.AddressID,
			ShareID:    protonDrive.MainShare.ShareID,
			LinkID:     linkID,
			RevisionID: revisionID,
			BlockList:  blockList,
		}
		blockUploadResp, err := protonDrive.c.RequestBlockUpload(ctx, blockUploadReq)
		if err != nil {
			return err
		}
		batchCtx, cancelBatch := context.WithCancel(ctx)
		defer cancelBatch()
		errChan := make(chan error, len(blockUploadResp))
		for i := range blockUploadResp {
			go func(i int) {
				if err := protonDrive.blockUploadSemaphore.Acquire(batchCtx, 1); err != nil {
					errChan <- err
					return
				}
				defer protonDrive.blockUploadSemaphore.Release(1)
				errChan <- protonDrive.c.UploadBlock(batchCtx, blockUploadResp[i].BareURL, blockUploadResp[i].Token, bytes.NewReader(pendingUploadBlocks[i].encData))
			}(i)
		}
		for i := 0; i < len(blockUploadResp); i++ {
			if err := <-errChan; err != nil {
				cancelBatch()
				return err
			}
		}
		pendingUploadBlocks = pendingUploadBlocks[:0]
		return nil
	}

	shouldContinue := true
	sha1Digests := sha1.New()
	blockSizes := make([]int64, 0)
	for i := 1; shouldContinue; i++ {
		if (i-1) > 0 && (i-1)%UPLOAD_BATCH_BLOCK_SIZE == 0 {
			err := uploadPendingBlocks()
			if err != nil {
				return nil, 0, nil, "", err
			}
		}

		data := make([]byte, UPLOAD_BLOCK_SIZE)
		readBytes, err := io.ReadFull(file, data)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				if readBytes == 0 {
					break
				}
				shouldContinue = false
			} else {
				return nil, 0, nil, "", err
			}
		}
		data = data[:readBytes]
		totalFileSize += int64(readBytes)
		sha1Digests.Write(data)
		blockSizes = append(blockSizes, int64(readBytes))

		dataPlainMessage := crypto.NewPlainMessage(data)
		encData, err := newSessionKey.Encrypt(dataPlainMessage)
		if err != nil {
			return nil, 0, nil, "", err
		}

		// Sign with primary key
		signature, err := protonDrive.primaryAddrKR.SignDetached(dataPlainMessage)
		if err != nil {
			return nil, 0, nil, "", err
		}

		// Web client logic for block signature:
		// 1. Sign plaintext to get detached signature
		// 2. Encrypt the detached signature using the session key AND the node key
		
		// Encrypt the signature with session key
		encSigBytes, err := newSessionKey.Encrypt(crypto.NewPlainMessage(signature.GetBinary()))
		if err != nil {
			return nil, 0, nil, "", err
		}
		
		// Encrypt with NodeKey
		encSigFull, err := newNodeKR.Encrypt(crypto.NewPlainMessage(encSigBytes), nil)
		if err != nil {
			return nil, 0, nil, "", err
		}
		
		encSignatureStr, err := encSigFull.GetArmored()
		if err != nil {
			return nil, 0, nil, "", err
		}

		h := sha256.New()
		h.Write(encData)
		hash := h.Sum(nil)
		base64Hash := base64.StdEncoding.EncodeToString(hash)
		manifestSignatureData = append(manifestSignatureData, hash...)

		// Verifier XOR Token
		vToken := make([]byte, len(vCode))
		for k := 0; k < len(vCode); k++ {
			blockByte := byte(0)
			if k < len(encData) {
				blockByte = encData[k]
			}
			vToken[k] = vCode[k] ^ blockByte
		}

		pendingUploadBlocks = append(pendingUploadBlocks, PendingUploadBlocks{
			blockUploadInfo: proton.BlockUploadInfo{
				Index:        i,
				Size:         int64(len(encData)),
				EncSignature: encSignatureStr,
				Hash:         base64Hash,
				Verifier: &proton.BlockVerifier{
					Token: base64.StdEncoding.EncodeToString(vToken),
				},
			},
			encData: encData,
		})
	}
	err = uploadPendingBlocks()
	if err != nil {
		return nil, 0, nil, "", err
	}

	sha1Hash := sha1Digests.Sum(nil)
	sha1String := hex.EncodeToString(sha1Hash)
	return manifestSignatureData, totalFileSize, blockSizes, sha1String, nil
}

func (protonDrive *ProtonDrive) commitNewRevision(ctx context.Context, nodeKR *crypto.KeyRing, xAttrCommon *proton.RevisionXAttrCommon, manifestSignatureData []byte, linkID, revisionID string) error {
	// Sign raw binary concatenation of hashes
	manifestSignature, err := protonDrive.primaryAddrKR.SignDetached(crypto.NewPlainMessage(manifestSignatureData))
	if err != nil {
		return err
	}
	manifestSignatureString, err := manifestSignature.GetArmored()
	if err != nil {
		return err
	}

	commitRevisionReq := proton.CommitRevisionReq{
		ManifestSignature: manifestSignatureString,
		SignatureAddress:  protonDrive.signatureAddress,
	}

	err = commitRevisionReq.SetEncXAttrString(protonDrive.primaryAddrKR, nodeKR, xAttrCommon)
	if err != nil {
		return err
	}

	err = protonDrive.c.CommitRevision(ctx, protonDrive.MainShare.ShareID, linkID, revisionID, commitRevisionReq)
	if err != nil {
		return err
	}

	return nil
}

func (protonDrive *ProtonDrive) uploadFile(ctx context.Context, parentLink *proton.Link, filename string, modTime time.Time, file io.Reader, testParam int) (string, *proton.RevisionXAttrCommon, error) {
	mimeType := mime.TypeByExtension(filepath.Ext(filename))
	if mimeType == "" {
		mimeType = "text/plain"
	}

	linkID, revisionID, newSessionKey, newNodeKR, err := protonDrive.createFileUploadDraft(ctx, parentLink, filename, modTime, mimeType)
	if err != nil {
		return "", nil, err
	}
	if testParam == 1 {
		return "", nil, nil
	}

	manifestSignature, fileSize, blockSizes, digests, err := protonDrive.uploadAndCollectBlockData(ctx, newSessionKey, newNodeKR, file, linkID, revisionID)
	if err != nil {
		return "", nil, err
	}
	if testParam == 2 {
		return "", nil, nil
	}

	/* step 3: mark the file as active by commiting the revision */
	xAttrCommon := &proton.RevisionXAttrCommon{
		ModificationTime: modTime.UTC().Format("2006-01-02T15:04:05.000Z"),
		Size:             fileSize,
		BlockSizes:       blockSizes,
		Digests: map[string]string{
			"SHA1": digests,
		},
	}
	err = protonDrive.commitNewRevision(ctx, newNodeKR, xAttrCommon, manifestSignature, linkID, revisionID)
	if err != nil {
		return "", nil, err
	}

	return linkID, xAttrCommon, nil
}

func (protonDrive *ProtonDrive) UploadFileByReader(ctx context.Context, parentLinkID string, filename string, modTime time.Time, file io.Reader, testParam int) (string, *proton.RevisionXAttrCommon, error) {
	parentLink, err := protonDrive.getLink(ctx, parentLinkID)
	if err != nil {
		return "", nil, err
	}
	return protonDrive.uploadFile(ctx, parentLink, filename, modTime, file, testParam)
}

func (protonDrive *ProtonDrive) UploadFileByPath(ctx context.Context, parentLink *proton.Link, filename string, filePath string, testParam int) (string, *proton.RevisionXAttrCommon, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	info, err := os.Stat(filePath)
	if err != nil {
		return "", nil, err
	}
	in := bufio.NewReader(f)
	return protonDrive.uploadFile(ctx, parentLink, filename, info.ModTime(), in, testParam)
}
