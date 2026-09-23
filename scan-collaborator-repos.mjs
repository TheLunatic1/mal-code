import { Octokit } from "@octokit/rest";
import dotenv from "dotenv";

dotenv.config();

const TOKEN = process.env.GITHUB_TOKEN;
const octokit = new Octokit({ auth: TOKEN });

async function check() {
  console.log("Fetching all repos for user (owner, collaborator, org member)...");
  const repos = await octokit.paginate(
    octokit.rest.repos.listForAuthenticatedUser,
    { per_page: 100, affiliation: "owner,collaborator,organization_member" }
  );

  console.log(`Total accessible repositories: ${repos.length}`);
  for (const r of repos) {
    if (r.full_name.toLowerCase().includes("1of1") || r.owner.login !== "TheLunatic1") {
      console.log(`  - ${r.full_name} (permissions: push=${r.permissions?.push}, admin=${r.permissions?.admin})`);
    }
  }
}

check().catch(console.error);
