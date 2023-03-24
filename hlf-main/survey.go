package main

import (
  "encoding/json"
  "fmt"
  "log"
  "time"
  "strings"

  "github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SmartContract provides functions for managing an Asset
   type SmartContract struct {
      contractapi.Contract
    }

// Asset describes basic details of what makes up a simple asset
    type Asset struct {
      ID             string `json:"ID"`
      Description    string `json:"description"`
      Fields         string `json:fields`
      CIDs           string `json:"cids"`
      Deadline       string `json:"dealine"`
    }


// CreateAsset issues a new asset to the world state with given details.
   func (s *SmartContract) CreateSurvey(ctx contractapi.TransactionContextInterface, id string, description string, fields string, deadline_str string) error {
    exists, err := s.SurveyExists(ctx, id)
    if err != nil {
      return err
    }
    if exists {
      return fmt.Errorf("There exists a survey with the same id %s", id)
    }

    layout := "2006-01-02 15:04:05"
    deadline, err_time := time.Parse(layout,deadline_str)
    deadline_str = deadline.Format("2006-01-02 15:04:05")

    if err_time != nil{
      return err_time
    }

    asset := Asset{
      ID:             id,
      Description:    description,
      Fields:         fields,
      CIDs:           "",
      Deadline:      deadline_str,
    }
    assetJSON, err := json.Marshal(asset)
    if err != nil {
      return err
    }

    return ctx.GetStub().PutState(id, assetJSON)
  }

// ReadAsset returns the asset stored in the world state with given id.
   func (s *SmartContract) ReadSurvey(ctx contractapi.TransactionContextInterface, id string) (*Asset, error) {
    assetJSON, err := ctx.GetStub().GetState(id)
    if err != nil {
      return nil, fmt.Errorf("failed to read survey: %v", err)
    }
    if assetJSON == nil {
      return nil, fmt.Errorf("the survey %s does not exist", id)
    }

    var asset Asset
    err = json.Unmarshal(assetJSON, &asset)
    if err != nil {
      return nil, err
    }

    return &asset, nil
  }


  // DeleteAsset deletes an given asset from the world state.
  func (s *SmartContract) DeleteSurvey(ctx contractapi.TransactionContextInterface, id string) error {
    exists, err := s.SurveyExists(ctx, id)
    if err != nil {
      return err
    }
    if !exists {
      return fmt.Errorf("the survey %s does not exist", id)
    }

    return ctx.GetStub().DelState(id)
  }

// AssetExists returns true when asset with given ID exists in world state
   func (s *SmartContract) SurveyExists(ctx contractapi.TransactionContextInterface, id string) (bool, error) {
    assetJSON, err := ctx.GetStub().GetState(id)
    if err != nil {
      return false, fmt.Errorf("failed to read from world state: %v", err)
    }

    return assetJSON != nil, nil
  }




// GetAllAssets returns all assets found in world state
   func (s *SmartContract) GetAllSurveys(ctx contractapi.TransactionContextInterface) ([]*Asset, error) {
// range query with empty string for startKey and endKey does an
// open-ended query of all assets in the chaincode namespace.
    resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
    if err != nil {
      return nil, err
    }
    defer resultsIterator.Close()

    var assets []*Asset
    for resultsIterator.HasNext() {
      queryResponse, err := resultsIterator.Next()
      if err != nil {
        return nil, err
      }

      var asset Asset
      err = json.Unmarshal(queryResponse.Value, &asset)
      if err != nil {
        return nil, err
      }
      assets = append(assets, &asset)
    }

    return assets, nil
  }

  //Add cid of a ipfs file to the list of cids in the survey
     func (s *SmartContract) AddCID(ctx contractapi.TransactionContextInterface, id string, cid string) error {
      asset, err := s.ReadSurvey(ctx, id)
      if err != nil {
        return err
      }

      //search the cid in the list and deleted if found
      cids := asset.CIDs

      index := strings.Index(cid, ";")
      if index != -1 {
        return fmt.Errorf("Invalid CID: %s ", cid)
      }

      index = strings.Index(cids, cid)
      if index != -1 {
        return fmt.Errorf("The CID %s is already on the list of IPFS CIDs", cid)
      }


      asset.CIDs = cids + cid + ";"

      assetJSON, err := json.Marshal(asset)
      if err != nil {
        return err
      }

      return ctx.GetStub().PutState(id, assetJSON)
    }

    //Delete cid of the list of cids of a survey
       func (s *SmartContract) RemoveCID(ctx contractapi.TransactionContextInterface, id string, cid string) error {
        asset, err := s.ReadSurvey(ctx, id)
        if err != nil {
          return err
        }

        //search the cid in the list and deleted if found
        cids := asset.CIDs
        index := strings.Index(cids, cid)
        if index == -1 {
          return fmt.Errorf("The CID %d does not exist in this survey", index)
        }
        cids = strings.ReplaceAll(cids, cid + ";", "")
        asset.CIDs = cids

        assetJSON, err := json.Marshal(asset)
        if err != nil {
          return err
        }

        return ctx.GetStub().PutState(id, assetJSON)
      }



  func main() {
    assetChaincode, err := contractapi.NewChaincode(&SmartContract{})
    if err != nil {
      log.Panicf("Error creating asset-transfer-basic chaincode: %v", err)
    }

    if err := assetChaincode.Start(); err != nil {
      log.Panicf("Error starting asset-transfer-basic chaincode: %v", err)
    }
  }
