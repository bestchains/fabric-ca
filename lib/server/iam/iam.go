/*
Copyright TenxCloud. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package iam

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	causer "github.com/hyperledger/fabric-ca/lib/server/user"
	"github.com/hyperledger/fabric-ca/lib/spi"
	ctls "github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/jmoiron/sqlx"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var errNotSupported = errors.New("not support")

const (
	iamGetUser = "%s/user/%s"
	iamLogin   = "%s/login"
	bestchain  = "bestchains"
)

// IAM Config
type Config struct {
	Enabled bool   `def:"false" help:"Enable the IAM client for authentication and attributes"`
	URL     string `help:"IAM server URL of form https://iam-server.svc.cluster.local" mask:"url"`
	// Attribute AttrConfig
	TLS ctls.ClientTLSConfig
}

func (c Config) String() string {
	return fmt.Sprintf("{ Enabled: %v, URL: %s }", c.Enabled, c.URL)
}

type BlockchainAnnotation struct {
	// Organization defines which organization this annotation is for
	Organization string `json:"organization,omitempty"`
	// IDs stores all Fabric-CA identities under this User's government
	IDs                   map[string]ID `json:"ids,omitempty"`
	CreationTimestamp     metav1.Time   `json:"creationTimestamp,omitempty"`
	LastAppliedTimestamp  metav1.Time   `json:"lastAppliedTimestamp,omitempty"`
	LastDeletionTimestamp metav1.Time   `json:"lastDeletionTimestamp,omitempty"`
}

type IDType string

const (
	ADMIN   IDType = "admin"
	CLIENT  IDType = "client"
	PEER    IDType = "peer"
	ORDERER IDType = "orderer"
)

// ID stands for a Fabric-CA identity
type ID struct {
	Name                 string            `json:"name"`
	Type                 IDType            `json:"type"`
	Attributes           map[string]string `json:"attributes,omitempty"`
	CreationTimestamp    metav1.Time       `json:"creationTimestamp,omitempty"`
	LastAppliedTimestamp metav1.Time       `json:"lastAppliedTimestamp,omitempty"`
}

type UserAnnotations struct {
	// List stores User's BlockchainAnnotation in different organizations
	List                    map[string]BlockchainAnnotation `json:"list,omitempty"`
	CreationTimestamp       metav1.Time                     `json:"creationTimestamp,omitempty"`
	LastAppliedTimestamp    metav1.Time                     `json:"lastAppliedTimestamp,omitempty"`
	LastDeletetionTimestamp metav1.Time                     `json:"lastDeletetionTimestamp,omitempty"`
}

type iamClient struct {
	iamCfg         Config
	organizationID string
}

type iamUser struct {
	Name        string            `json:"name"`
	Annotations map[string]string `json:"annotations"`

	// Used to save the user's attributes
	UA map[string]string

	Role   string   `json:"role"`
	Groups []string `json:"groups"`

	url       string
	transport http.RoundTripper
}

func NewIAMClient(cfg *Config, orgID string) *iamClient {
	log.Debugf("IAM orgID %s\n", orgID)
	return &iamClient{
		iamCfg:         *cfg,
		organizationID: orgID,
	}
}

// GetUser
// The username parameter consists of two parts, name and token, which are separated by a colon.
// The attrNames parameter is mainly used for peer and order authentication.
// If attrNames is not empty, it tries to find out if this information exists from the User's Annotations.
func (c *iamClient) GetUser(username string, attrNames []string) (causer.User, error) {
	nameWithToken := strings.Split(username, ":")
	if len(nameWithToken) != 2 {
		log.Debugf("IAM GetUser try to split username %s %v, can't get right array.", username, nameWithToken)
		return nil, fmt.Errorf("IAM can't parse username")
	}

	url := fmt.Sprintf(iamGetUser, c.iamCfg.URL, nameWithToken[0])
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Debugf("IAM GetUser new request error: %s", err)
		return nil, err
	}

	req.Header.Add("Authorization", nameWithToken[1])
	req.Header.Add("Content-Type", "application/json")

	u := &iamUser{url: c.iamCfg.URL}
	client := &http.Client{}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	// if strings.HasPrefix(c.iamCfg.URL, "https") {
	// 	log.Debugf("IAM GetUser set https")
	// 	certPool := x509.NewCertPool()
	// 	for _, f := range c.iamCfg.TLS.CertFiles {
	// 		fBytes, _ := os.ReadFile(f)
	// 		certPool.AppendCertsFromPEM(fBytes)
	// 	}

	// 	transport.TLSClientConfig.InsecureSkipVerify = false
	// 	transport.TLSClientConfig.RootCAs = certPool

	// 	if c.iamCfg.TLS.Client.CertFile != "" && c.iamCfg.TLS.Client.KeyFile != "" {
	// 		cert, err := tls.LoadX509KeyPair(c.iamCfg.TLS.Client.CertFile, c.iamCfg.TLS.Client.KeyFile)
	// 		if err != nil {
	// 			log.Debugf("IAM GetUser try to load client x509keypair error: %s\n", err)
	// 			return nil, err
	// 		}
	// 		transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
	// 	}
	// }
	client.Transport = transport
	u.transport = transport

	response, err := client.Do(req)
	if err != nil {
		log.Debugf("IAM GetUser do request to %s error: %s\n", url, err)
		return nil, err
	}

	defer response.Body.Close()
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		log.Debugf("IAM GetUser read response body error %s\n", err)
		return nil, err
	}

	if err = json.Unmarshal(bodyBytes, &u); err != nil {
		log.Debugf("IAM GetUser unmarshal body error: %s\n", err)
		return nil, err
	}

	log.Debugf("IAM GetUser unmarshal user annotations\n")
	u.UA = make(map[string]string)

	/*
		If the User's annotations contain the key bestchains.
		annotation structure:
		{
		    "list":{
		        "org1":{
		            "organization":"org1",
		            "namespace":"org1",
		            "ids":{
		                "org1admin":{
		                    "name":"org1admin",
		                    "type":"admin",
		                    "attributes":{
		                        "hf.Affiliation":"",
								...
		                    },
		                    "creationTime":"2022-12-22 14:34:00.681636 +0800 CST m=+135.544195580"
		                }
		            }
		        }
		    },
		    "lastAppliedTime":"2022-12-22 14:34:00.681644 +0800 CST m=+135.544203511"
		}
	*/
	if chains, ok := u.Annotations[bestchain]; ok {
		ua := UserAnnotations{}
		if err = json.Unmarshal([]byte(chains), &ua); err != nil {
			log.Debugf("IAM GetUser unmarshal %s error: %s\n", chains, err)
			return nil, err
		}
		orgInfo, ok := ua.List[c.organizationID]
		if !ok {
			return nil, fmt.Errorf("don't have any organization infomration")
		}
		if len(orgInfo.IDs) == 0 {
			return nil, fmt.Errorf("can't verify user %s", attrNames[0])
		}
		if len(attrNames) > 0 {
			peerOrOrder, ok := orgInfo.IDs[attrNames[0]]
			if !ok {
				return nil, fmt.Errorf("can't find user %s from ids", attrNames[0])
			}

			u.Name = peerOrOrder.Name
			u.Role = string(peerOrOrder.Type)
			u.UA = peerOrOrder.Attributes
		} else {
			userAtrrs, ok := orgInfo.IDs[nameWithToken[0]]
			if !ok {
				return nil, fmt.Errorf("can't find request user %s", nameWithToken[0])
			}
			u.UA = userAtrrs.Attributes
			u.Role = string(userAtrrs.Type)
		}
	}

	return u, nil
}

func (c *iamClient) InsertUser(u *causer.Info) error {
	return errNotSupported
}

func (c *iamClient) UpdateUser(u *causer.Info, updatePass bool) error {
	return errNotSupported
}

func (c *iamClient) DeleteUser(id string) (causer.User, error) {
	return nil, errNotSupported
}

func (c *iamClient) GetAffiliation(name string) (spi.Affiliation, error) {
	return nil, errNotSupported
}

func (c *iamClient) GetAllAffiliations(name string) (*sqlx.Rows, error) {
	return nil, errNotSupported
}

func (c *iamClient) GetRootAffiliation() (spi.Affiliation, error) {
	return nil, errNotSupported
}

func (c *iamClient) InsertAffiliation(name, prekey string, version int) error {
	return errNotSupported
}

func (c *iamClient) DeleteAffiliation(name string, force, identityRemoval, isRegistrar bool) (*causer.DbTxResult, error) {
	return nil, errNotSupported
}

func (c *iamClient) ModifyAffiliation(oldAffiliation, newAffiliation string, force, isRegistrar bool) (*causer.DbTxResult, error) {
	return nil, errNotSupported
}

func (c *iamClient) GetUserLessThanLevel(version int) ([]causer.User, error) {
	return nil, errNotSupported
}

func (c *iamClient) GetFilteredUsers(affiliation, types string) (*sqlx.Rows, error) {
	return nil, errNotSupported
}

func (c *iamClient) GetAffiliationTree(name string) (*causer.DbTxResult, error) {
	return nil, errNotSupported
}

func (u *iamUser) GetName() string {
	return u.Name
}

func (u *iamUser) GetType() string {
	return u.Role
}

func (u *iamUser) GetMaxEnrollments() int {
	return 0
}

func (u *iamUser) GetLevel() int {
	return 0
}

func (u *iamUser) SetLevel(int) error {
	return errNotSupported
}

func (u *iamUser) Login(password string, canMaxEnrollment int) error {
	body := map[string]string{
		"name":     u.Name,
		"password": password,
	}

	bodyBytes, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf(iamLogin, u.url), bytes.NewReader(bodyBytes))
	if err != nil {
		log.Debugf("iamUser Login try generate requeste error: %s\n", err)
		return err
	}

	client := &http.Client{}
	if u.transport != nil {
		client.Transport = u.transport
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Debugf("iamUser Login do request error: %s\n", err)
		return err
	}

	if resp.StatusCode != http.StatusOK {
		log.Debugf("iamUser Login failed, raw resp: %#v\n", resp)
		return fmt.Errorf("user login does not give the expected result, response code: %d", resp.StatusCode)
	}
	return nil
}

func (u *iamUser) LoginComplete() error {
	return nil
}

// TODO: No implementation for now
func (u *iamUser) GetAffiliationPath() []string {
	return []string{}
}

func (u *iamUser) GetAttribute(name string) (*api.Attribute, error) {
	values, ok := u.UA[name]
	if !ok {
		return nil, fmt.Errorf("can't find request attribute %s", name)
	}
	return &api.Attribute{Name: name, Value: values}, nil
}

func (u *iamUser) GetAttributes(attrNames []string) ([]api.Attribute, error) {
	attrs := make([]api.Attribute, 0)
	if len(attrNames) == 0 {
		for k, v := range u.UA {
			attrs = append(attrs, api.Attribute{Name: k, Value: v, ECert: true})
		}
		return attrs, nil
	}

	for _, name := range attrNames {
		attr, err := u.GetAttribute(name)
		if err != nil {
			log.Debugf("iamUser get attribute by name %s errro: %s", name, err)
			return nil, err
		}
		attrs = append(attrs, *attr)
	}
	return attrs, nil
}

// TODO: No implementation for now
func (u *iamUser) Revoke() error {
	return errNotSupported
}

func (u *iamUser) IsRevoked() bool {
	return false
}

func (u *iamUser) ModifyAttributes(attrs []api.Attribute) error {
	return errNotSupported
}

func (u *iamUser) IncrementIncorrectPasswordAttempts() error {
	return errNotSupported
}

func (u *iamUser) GetFailedLoginAttempts() int {
	return 0
}
