const assert = require("node:assert/strict");
const { test } = require("node:test");
const syncUpstream = require("./sync-upstream.cjs");

const branch = "automation/upstream-upstream-one";
const repo = process.env.TEST_REPO || "s2";
const upstream = `s2-streamstore/${repo}`;

function proposal({
	draft = true,
	number = 10,
	sha = "upstream-one",
	state = "open",
} = {}) {
	return {
		base: { ref: "main" },
		draft,
		head: { ref: branch, repo: { full_name: `zshannon/${repo}` }, sha },
		html_url: `https://github.com/zshannon/${repo}/pull/${number}`,
		node_id: `PR_${number}`,
		number,
		state,
	};
}

function fixture({
	base = "base",
	prs = [],
	ref = branch,
	tip,
	upstreamSha = "upstream-one",
} = {}) {
	const graph = {
		base: ["parent"],
		integrated: ["resolved"],
		parent: [],
		resolved: ["base", "upstream-one"],
		rewritten: ["parent"],
		"upstream-one": ["parent"],
		"upstream-two": ["upstream-one"],
	};
	const state = {
		base,
		fail: undefined,
		prs: structuredClone(prs),
		refs: tip ? { [ref]: tip } : {},
		tip,
		upstreamSha,
		writes: [],
	};
	const resolve = (ref) =>
		ref === "main"
			? state.base
			: ref === "s2-streamstore:main"
				? state.upstreamSha
				: ref;
	const ancestors = (sha) =>
		new Set([sha, ...graph[sha].flatMap((parent) => [...ancestors(parent)])]);
	const write = (kind, args) => {
		if (state.fail === kind) {
			state.fail = undefined;
			throw Object.assign(new Error(`${kind} failed`), { status: 503 });
		}
		state.writes.push({ args: structuredClone(args), kind });
	};
	const github = {
		graphql: async (_query, args) => {
			write("draft", args);
			state.prs.find((pr) => pr.node_id === args.id).draft = true;
		},
		paginate: async (method, args) => (await method(args)).data,
		rest: {
			git: {
				createRef: async (args) => {
					write("create-ref", args);
					assert.equal(
						state.refs[args.ref.slice("refs/heads/".length)],
						undefined,
					);
					state.refs[args.ref.slice("refs/heads/".length)] = args.sha;
					state.tip = args.sha;
					return { data: { object: { sha: state.tip } } };
				},
				getRef: async (args) => {
					const sha = state.refs[args.ref.slice("heads/".length)];
					if (!sha)
						throw Object.assign(new Error("Not Found"), { status: 404 });
					return { data: { object: { sha } } };
				},
				updateRef: async (args) => {
					write("update-ref", args);
					const ref = args.ref.slice("heads/".length);
					assert.equal(
						args.force,
						false,
						"never force-push an automation branch",
					);
					assert(
						ancestors(args.sha).has(state.refs[ref]),
						"non-fast-forward push",
					);
					state.refs[ref] = args.sha;
					state.tip = args.sha;
					for (const pr of state.prs.filter(
						(pr) => pr.state === "open" && pr.head.ref === ref,
					))
						pr.head.sha = state.tip;
					return { data: { object: { sha: state.tip } } };
				},
			},
			pulls: {
				create: async (args) => {
					write("create-pr", args);
					const pr = proposal({
						draft: args.draft,
						number: 20,
						sha: state.tip,
					});
					pr.head.ref = args.head.split(":").at(-1);
					if (args.head === "s2-streamstore:main")
						pr.head = {
							ref: "main",
							repo: { full_name: upstream },
							sha: state.upstreamSha,
						};
					state.prs.push(pr);
					return { data: pr };
				},
				list: async (args) => ({
					data: state.prs.filter(
						(pr) =>
							(args.state === "all" || args.state === pr.state) &&
							pr.base.ref === args.base &&
							(!args.head ||
								args.head ===
									`${pr.head.repo.full_name.split("/")[0]}:${pr.head.ref}`),
					),
				}),
				update: async (args) => {
					write("close-pr", args);
					state.prs.find((pr) => pr.number === args.pull_number).state =
						args.state;
					return { data: {} };
				},
			},
			repos: {
				compareCommitsWithBasehead: async (args) => {
					if (state.fail === "compare")
						throw Object.assign(new Error("compare failed"), { status: 503 });
					const [left, right] = args.basehead.split("...").map(resolve);
					const from = ancestors(left);
					const to = ancestors(right);
					const ahead_by = [...to].filter((sha) => !from.has(sha)).length;
					const behind_by = [...from].filter((sha) => !to.has(sha)).length;
					return {
						data: {
							ahead_by,
							behind_by,
							status:
								!ahead_by && !behind_by
									? "identical"
									: !behind_by
										? "ahead"
										: !ahead_by
											? "behind"
											: "diverged",
						},
					};
				},
				getBranch: async (args) => ({
					data: {
						commit: {
							sha:
								args.owner === "s2-streamstore"
									? state.upstreamSha
									: state.base,
						},
					},
				}),
			},
		},
	};
	const run = () =>
		syncUpstream({
			context: { repo: { owner: "zshannon", repo } },
			core: { info() {} },
			github,
		});
	return { run, state };
}

function legacy() {
	const pr = proposal({ draft: false, number: 4 });
	pr.head = { ref: "main", repo: { full_name: upstream }, sha: "upstream-one" };
	return pr;
}

const kinds = (state) => state.writes.map((write) => write.kind);

test("already integrated upstream causes no writes", async () => {
	const { run, state } = fixture({ base: "integrated" });
	await run();
	assert.deepEqual(state.writes, []);
});

test("new candidate uses a fork-owned snapshot and draft PR", async () => {
	const { run, state } = fixture();
	await run();
	assert.equal(state.tip, "upstream-one");
	assert.deepEqual(kinds(state), ["create-ref", "create-pr"]);
	const args = state.writes.at(-1).args;
	assert.equal(args.base, "main");
	assert.equal(args.draft, true);
	assert.equal(args.head, `zshannon:${branch}`);
	assert.match(args.body, /merge commit/);
});

test("legacy tracking PR closes only after an editable replacement exists", async () => {
	const { run, state } = fixture({ prs: [legacy()] });
	await run();
	assert.deepEqual(kinds(state), ["create-ref", "create-pr", "close-pr"]);
	assert.equal(state.prs[0].state, "closed");
	assert.match(state.writes[1].args.body, /pull\/4/);
});

test("unchanged proposal is a complete no-op, including readiness", async () => {
	const { run, state } = fixture({
		prs: [proposal({ draft: false })],
		tip: "upstream-one",
	});
	await run();
	await run();
	assert.deepEqual(state.writes, []);
	assert.equal(state.prs[0].draft, false);
});

test("new upstream commits draft the PR before one fast-forward update", async () => {
	const { run, state } = fixture({
		prs: [proposal({ draft: false })],
		tip: "upstream-one",
		upstreamSha: "upstream-two",
	});
	await run();
	assert.deepEqual(kinds(state), ["draft", "update-ref"]);
	assert.equal(state.writes[1].args.force, false);
	assert.equal(state.tip, "upstream-two");
	state.writes = [];
	await run();
	assert.deepEqual(state.writes, []);
});

test("new commits on an already-draft PR do not edit the PR", async () => {
	const { run, state } = fixture({
		prs: [proposal()],
		tip: "upstream-one",
		upstreamSha: "upstream-two",
	});
	await run();
	assert.deepEqual(kinds(state), ["update-ref"]);
});

test("human conflict resolutions remain untouched", async () => {
	const { run, state } = fixture({
		prs: [proposal({ draft: false, sha: "resolved" })],
		tip: "resolved",
		upstreamSha: "upstream-two",
	});
	await run();
	assert.deepEqual(state.writes, []);
	assert.equal(state.tip, "resolved");
});

test("upstream history rewrite does not discard an existing proposal", async () => {
	const { run, state } = fixture({
		prs: [proposal()],
		tip: "upstream-one",
		upstreamSha: "rewritten",
	});
	await run();
	assert.deepEqual(state.writes, []);
});

test("closed proposal for the exact candidate stays closed", async () => {
	const { run, state } = fixture({
		prs: [proposal({ state: "closed" })],
		tip: "upstream-one",
	});
	await run();
	assert.deepEqual(state.writes, []);
});

test("old closed proposal does not block a newer candidate on a reused branch", async () => {
	const { run, state } = fixture({
		prs: [proposal({ state: "closed" })],
		ref: "automation/upstream-upstream-two",
		tip: "upstream-two",
		upstreamSha: "upstream-two",
	});
	await run();
	assert.deepEqual(kinds(state), ["create-pr"]);
	assert.equal(state.prs.at(-1).head.sha, "upstream-two");
});

test("branch creation followed by a failed PR request recovers without another push", async () => {
	const { run, state } = fixture({ prs: [legacy()] });
	state.fail = "create-pr";
	await assert.rejects(run, /create-pr failed/);
	assert.equal(state.prs[0].state, "open");
	state.writes = [];
	await run();
	assert.deepEqual(kinds(state), ["create-pr", "close-pr"]);
});

test("migration closure failure retries without a duplicate PR or branch update", async () => {
	const { run, state } = fixture({ prs: [legacy()] });
	state.fail = "close-pr";
	await assert.rejects(run, /close-pr failed/);
	state.writes = [];
	await run();
	assert.deepEqual(kinds(state), ["close-pr"]);
});

test("after a resolved proposal merges, a fresh branch preserves the previous branch", async () => {
	const { run, state } = fixture({
		base: "integrated",
		prs: [proposal({ sha: "resolved", state: "closed" })],
		tip: "resolved",
		upstreamSha: "upstream-two",
	});
	await run();
	assert.deepEqual(kinds(state), ["create-ref", "create-pr"]);
	assert.equal(state.refs[branch], "resolved");
	assert.equal(state.refs["automation/upstream-upstream-two"], "upstream-two");
	assert.equal(state.base, "integrated");
});

test("a new candidate after a declined proposal preserves its human commits", async () => {
	const { run, state } = fixture({
		prs: [proposal({ sha: "resolved", state: "closed" })],
		tip: "resolved",
		upstreamSha: "upstream-two",
	});
	await run();
	assert.deepEqual(kinds(state), ["create-ref", "create-pr"]);
	assert.equal(state.refs[branch], "resolved");
});

test("a ready PR is left unchanged if moving it to draft fails", async () => {
	const { run, state } = fixture({
		prs: [proposal({ draft: false })],
		tip: "upstream-one",
		upstreamSha: "upstream-two",
	});
	state.fail = "draft";
	await assert.rejects(run, /draft failed/);
	assert.equal(state.tip, "upstream-one");
	assert.deepEqual(state.writes, []);
});

test("API failures remain failures instead of successful empty checks", async () => {
	const { run, state } = fixture();
	state.fail = "compare";
	await assert.rejects(run, /compare failed/);
	assert.deepEqual(state.writes, []);
});

test("other forks cannot be mistaken for the automation proposal", async () => {
	const unrelated = proposal();
	unrelated.head.repo.full_name = `someone-else/${repo}`;
	const { run, state } = fixture({ prs: [unrelated] });
	await run();
	assert.deepEqual(kinds(state), ["create-ref", "create-pr"]);
	assert.equal(state.prs[0].state, "open");
});

test("a declined candidate with human resolutions is not proposed again", async () => {
	const { run, state } = fixture({
		prs: [proposal({ sha: "resolved", state: "closed" })],
		tip: "resolved",
	});
	await run();
	assert.deepEqual(state.writes, []);
});

test("multiple active proposals require attention instead of guessing which to update", async () => {
	const { run, state } = fixture({
		prs: [proposal(), proposal({ number: 11 })],
		tip: "upstream-one",
	});
	await assert.rejects(run, /Multiple upstream proposals/);
	assert.deepEqual(state.writes, []);
});

test("migration closure still recovers after a human resolves the new PR", async () => {
	const { run, state } = fixture({ prs: [legacy()] });
	state.fail = "close-pr";
	await assert.rejects(run, /close-pr failed/);
	state.refs[branch] = "resolved";
	state.tip = "resolved";
	state.prs.at(-1).head.sha = "resolved";
	state.writes = [];
	await run();
	assert.deepEqual(kinds(state), ["close-pr"]);
	assert.equal(state.refs[branch], "resolved");
});
