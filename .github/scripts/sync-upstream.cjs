// Runs only from the default branch with a repository-scoped automation token.
// Never executes upstream code or changes main.
module.exports = async function syncUpstream({ context, core, github }) {
	const { owner, repo } = context.repo;
	const base = "main";
	const prefix = "automation/upstream-";
	const upstreamOwner = "s2-streamstore";
	const repository = `${owner}/${repo}`;
	const upstreamRepository = `${upstreamOwner}/${repo}`;
	const compare = async (left, right) =>
		(
			await github.rest.repos.compareCommitsWithBasehead({
				basehead: `${left}...${right}`,
				owner,
				per_page: 1,
				repo,
			})
		).data;
	const [{ data: main }, { data: upstream }] = await Promise.all([
		github.rest.repos.getBranch({ branch: base, owner, repo }),
		github.rest.repos.getBranch({ branch: base, owner: upstreamOwner, repo }),
	]);
	const baseSha = main.commit.sha;
	const candidate = upstream.commit.sha;
	if ((await compare(baseSha, candidate)).ahead_by === 0) {
		core.info("No upstream commits need merging.");
		return;
	}

	const proposals = (
		await github.paginate(github.rest.pulls.list, {
			base,
			owner,
			per_page: 100,
			repo,
			state: "all",
		})
	).filter(
		(pr) =>
			pr.head.repo?.full_name === repository && pr.head.ref.startsWith(prefix),
	);
	const open = proposals.filter((pr) => pr.state === "open");
	if (open.length > 1)
		throw new Error(
			"Multiple upstream proposals are open; choose one before syncing.",
		);
	let proposal = open[0];
	if (!proposal) {
		for (const pr of proposals.filter((pr) => pr.state === "closed")) {
			// Also respect a closed PR containing human resolutions of this candidate.
			// Older closed candidates do not suppress a new upstream SHA.
			if (
				pr.head.sha === candidate ||
				(await compare(candidate, pr.head.sha)).behind_by === 0
			) {
				core.info(
					"This upstream candidate was already proposed and closed; leaving it closed.",
				);
				return;
			}
		}
	}
	// One active PR, with a fresh branch for the next proposal after merge/closure.
	// Keeping completed branches avoids force-push races with human commits.
	const branch = proposal?.head.ref || `${prefix}${candidate}`;

	const legacy = (
		await github.paginate(github.rest.pulls.list, {
			base,
			head: `${upstreamOwner}:${base}`,
			owner,
			per_page: 100,
			repo,
			state: "open",
		})
	).filter((pr) => pr.head.repo?.full_name === upstreamRepository);

	const closeLegacy = async () => {
		// Close old cross-repository trackers only after their editable replacement exists.
		// Retrying a failed closure neither pushes again nor creates a duplicate PR.
		for (const pr of legacy) {
			await github.rest.pulls.update({
				owner,
				pull_number: pr.number,
				repo,
				state: "closed",
			});
			core.info(`Replaced ${pr.html_url} with ${proposal.html_url}`);
		}
	};

	let tip;
	try {
		tip = (
			await github.rest.git.getRef({ owner, ref: `heads/${branch}`, repo })
		).data.object.sha;
	} catch (error) {
		if (error.status !== 404) throw error;
	}

	if (!tip) {
		await github.rest.git.createRef({
			owner,
			ref: `refs/heads/${branch}`,
			repo,
			sha: candidate,
		});
	} else if (tip !== candidate) {
		const fastForward = (await compare(tip, candidate)).behind_by === 0;
		if (!fastForward) {
			if (proposal) await closeLegacy();
			core.info(
				`Leaving ${branch} unchanged: it contains work not in this upstream snapshot. Merge or resolve the existing proposal manually.`,
			);
			return;
		}
		// An updated snapshot has not been reviewed or validated yet. Draft it BEFORE
		// pushing, so a failed draft request cannot leave new code marked ready.
		if (proposal && !proposal.draft) {
			await github.graphql(
				`mutation($id: ID!) {
        convertPullRequestToDraft(input: { pullRequestId: $id }) { pullRequest { id } }
      }`,
				{ id: proposal.node_id },
			);
		}
		await github.rest.git.updateRef({
			force: false,
			owner,
			ref: `heads/${branch}`,
			repo,
			sha: candidate,
		});
	}

	if (!proposal) {
		const preserve =
			repo === "s2"
				? "Preserve the fork’s native Biscuit PKI authentication and deployment configuration."
				: "Preserve PKI behavior, the published Biscuit dependency, @zshannon package names, and release configuration.";
		const { data } = await github.rest.pulls.create({
			base,
			body: [
				`Integrate an upstream snapshot from \`${upstreamRepository}:main\` into this fork.`,
				"",
				"The Tuesday 09:00 America/Los_Angeles check owns this fork branch. An unchanged snapshot causes no push, PR edit, or CI dispatch. New or refreshed snapshots start in draft pending integration review and validation.",
				"",
				"Resolve conflicts on this branch by merging this fork’s main into it. Once this branch contains your own commits, the automation preserves them and leaves further integration to you.",
				preserve,
				"",
				"Review all changes, including workflows. If GitHub prompts for **Approve workflows to run**, approve after review and wait for required CI. Mark ready only when the update is ready for review; merge manually with a **merge commit** to retain upstream ancestry. Do not squash or rebase upstream imports.",
				"",
				"This workflow does not merge, publish, or deploy. It uses the repository-scoped UPSTREAM_SYNC_TOKEN to import commits, including upstream workflow changes.",
				...legacy.map(
					(pr) =>
						`\nReplaces the uneditable upstream tracking PR: ${pr.html_url}`,
				),
			].join("\n"),
			draft: true,
			head: `${owner}:${branch}`,
			maintainer_can_modify: true,
			owner,
			repo,
			title: "chore(upstream): integrate upstream main",
		});
		proposal = data;
		core.info(`Opened draft upstream proposal: ${proposal.html_url}`);
	} else {
		core.info(`Keeping upstream proposal: ${proposal.html_url}`);
	}

	await closeLegacy();
};
