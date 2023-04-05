import express, { Request, Response } from "express";
import * as jose from "jose";
import jsonld from "jsonld";
import crypto from "crypto";
import axios from "axios";
import {
  generateDID,
  generatePublicJWK,
  generateLegalPerson,
  normalize,
  sha256,
  createProof,
  verify,
} from "../utils/common-functions";
import { AppConst, AppMessages } from "../utils/constants";
export const privateRoute = express.Router();

privateRoute.post(
  "/createDID",
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { domain } = req.body;
      const didId = `did:web:${domain}`;
      const x5uURL = `https://${domain}/.well-known/x509CertificateChain.pem`;
      const certificate = (await axios.get(x5uURL)).data as string;
      const publicKeyJwk = await generatePublicJWK(
        jose,
        AppConst.RSA_ALGO,
        certificate,
        x5uURL
      );
      const did = generateDID(didId, publicKeyJwk);
      res.status(200).json({
        data: { did },
        message: AppMessages.DID_SUCCESS,
      });
    } catch (e) {
      res.status(422).json({
        data: { error: (e as Error).message },
        message: AppMessages.DID_FAILED,
      });
    }
  }
);

privateRoute.post(
  "/createLegalPerson",
  async (req: Request, res: Response): Promise<void> => {
    try {
      const {
        domain,
        legalName,
        legalRegistrationType,
        legalRegistrationNumber,
        headquarterAddress,
        legalAddress,
        privateKeyUrl,
      } = req.body;
      const didId = `did:web:${domain}`;
      const selfDescription = generateLegalPerson(
        didId,
        legalName,
        legalRegistrationType,
        legalRegistrationNumber,
        headquarterAddress,
        legalAddress
      );
      const canonizedSD = await normalize(jsonld, selfDescription);
      const hash = sha256(crypto, canonizedSD);
      console.log(`📈 Hashed canonized SD ${hash}`);
      // const privateKey = (await axios.get(privateKeyUrl)).data as string;
      const privateKey = process.env.PRIVATE_KEY as string;
      const proof = await createProof(
        jose,
        didId,
        AppConst.RSA_ALGO,
        hash,
        privateKey
      );
      console.log(proof ? "🔒 SD signed successfully" : "❌ SD signing failed");
      const x5uURL = `https://${domain}/.well-known/x509CertificateChain.pem`;
      const certificate = (await axios.get(x5uURL)).data as string;
      const publicKeyJwk = await generatePublicJWK(
        jose,
        AppConst.RSA_ALGO,
        certificate,
        x5uURL
      );
      const verificationResult = await verify(
        jose,
        proof.jws.replace("..", `.${hash}.`),
        AppConst.RSA_ALGO,
        publicKeyJwk
      );
      console.log(
        verificationResult?.content === hash
          ? "✅ Verification successful"
          : "❌ Verification failed"
      );
      selfDescription["verifiableCredential"][0].proof = proof;
      console.log(JSON.stringify(selfDescription))
      const complianceCredential = (await axios.post(process.env.COMPLIANCE_SERVICE as string,selfDescription)).data;
      console.log(
        complianceCredential
          ? "🔒 SD signed successfully (compliance service)"
          : "❌ SD signing failed (compliance service)"
      );
      const completeSd = {
        selfDescriptionCredential: selfDescription,
        complianceCredential: complianceCredential.complianceCredential,
      };

      res.status(200).json({
        data: { verifiableCredential: completeSd },
        message: AppMessages.SD_SUCCESS,
      });
    } catch (e) {
      console.log(e);
      res.status(422).json({
        data: { error: (e as Error).message },
        message: AppMessages.SD_FAILED,
      });
    }
  }
);
