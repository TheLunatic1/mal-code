#!/usr/bin/env node
/**
 * One-shot: Scan all repos + deploy malware-scan GitHub Action to infected ones.
 * Run: node scan-and-deploy.js
 */
import { Octokit } from "@octokit/rest";
import dotenv from "dotenv";
dotenv.config();

const TOKEN = process.env.GITHUB_TOKEN;
const octokit = new Octokit({ auth: TOKEN });

const MARKER = `
