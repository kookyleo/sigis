// Derived from pyhanko-certvalidator 0.33.0 policy_graph.py (MIT,
// see LICENSE-pyHanko). Private RFC 9618 graph used by path validation.

use std::collections::{BTreeMap, BTreeSet};

use const_oid::ObjectIdentifier;
use x509_cert::ext::pkix::certpolicy::{PolicyInformation, PolicyQualifierInfo};

use crate::path::QualifiedPolicy;

const ANY: ObjectIdentifier = const_oid::db::rfc5280::ANY_POLICY;
pub(super) type NodeId = usize;

#[derive(Debug, thiserror::Error)]
pub(super) enum GraphError {
    #[error("Policy graph is limited to {0} nodes")]
    SizeLimit(usize),
    #[error("Unknown policy graph node {0}")]
    UnknownNode(NodeId),
    #[error("Policy {policy} already occurs at depth {depth}")]
    Duplicate {
        policy: ObjectIdentifier,
        depth: usize,
    },
}

#[derive(Debug)]
pub(super) struct Node {
    pub(super) policy: ObjectIdentifier,
    pub(super) qualifiers: Vec<PolicyQualifierInfo>,
    pub(super) expected: BTreeSet<ObjectIdentifier>,
    pub(super) depth: usize,
    pub(super) parents: BTreeSet<NodeId>,
    pub(super) children: BTreeSet<NodeId>,
}

#[derive(Debug)]
pub(super) struct Graph {
    levels: Vec<BTreeMap<ObjectIdentifier, NodeId>>,
    nodes: BTreeMap<NodeId, Node>,
    childless: BTreeSet<NodeId>,
    next_id: NodeId,
    max_nodes: Option<usize>,
    // Detached Python nodes can still be observed through caller references.
    // Production releases their storage; tests preserve only that observation.
    #[cfg(test)]
    detached: BTreeMap<NodeId, Node>,
    #[cfg(test)]
    pub(super) prune_calls: Vec<usize>,
}

impl Graph {
    pub(super) fn new(max_nodes: Option<usize>) -> Self {
        Self {
            levels: vec![BTreeMap::from([(ANY, 0)])],
            nodes: BTreeMap::from([(
                0,
                Node {
                    policy: ANY,
                    qualifiers: Vec::new(),
                    expected: BTreeSet::from([ANY]),
                    depth: 0,
                    parents: BTreeSet::new(),
                    children: BTreeSet::new(),
                },
            )]),
            childless: BTreeSet::from([0]),
            next_id: 1,
            max_nodes,
            #[cfg(test)]
            detached: BTreeMap::new(),
            #[cfg(test)]
            prune_calls: Vec::new(),
        }
    }

    pub(super) fn depth(&self) -> usize {
        self.levels.len() - 1
    }
    pub(super) fn node_count(&self) -> usize {
        self.nodes.len()
    }
    pub(super) fn node_at(&self, depth: isize, policy: ObjectIdentifier) -> Option<NodeId> {
        self.levels
            .get(usize::try_from(depth).ok()?)?
            .get(&policy)
            .copied()
    }
    pub(super) fn nodes_at_depth(&self, depth: isize) -> Vec<NodeId> {
        usize::try_from(depth)
            .ok()
            .and_then(|d| self.levels.get(d))
            .map(|level| level.values().copied().collect())
            .unwrap_or_default()
    }
    pub(super) fn node(&self, id: NodeId) -> &Node {
        #[cfg(test)]
        if let Some(node) = self.detached.get(&id) {
            return node;
        }
        &self.nodes[&id]
    }
    pub(super) fn node_mut(&mut self, id: NodeId) -> Option<&mut Node> {
        self.nodes.get_mut(&id)
    }
    pub(super) fn add_node(
        &mut self,
        depth: usize,
        policy: ObjectIdentifier,
        qualifiers: Vec<PolicyQualifierInfo>,
        expected: BTreeSet<ObjectIdentifier>,
        parents: &[NodeId],
    ) -> Result<NodeId, GraphError> {
        if let Some(limit) = self.max_nodes.filter(|limit| self.node_count() >= *limit) {
            return Err(GraphError::SizeLimit(limit));
        }
        while self.levels.len() <= depth {
            self.levels.push(BTreeMap::new());
        }
        if self.levels[depth].contains_key(&policy) {
            return Err(GraphError::Duplicate { policy, depth });
        }
        let id = self.next_id;
        self.next_id += 1;
        let parents: BTreeSet<_> = parents.iter().copied().collect();
        for parent in &parents {
            if !self.nodes.contains_key(parent) {
                return Err(GraphError::UnknownNode(*parent));
            }
        }
        for parent in &parents {
            self.node_mut(*parent)
                .ok_or(GraphError::UnknownNode(*parent))?
                .children
                .insert(id);
            self.childless.remove(parent);
        }
        self.nodes.insert(
            id,
            Node {
                policy,
                qualifiers,
                expected,
                depth,
                parents,
                children: BTreeSet::new(),
            },
        );
        self.levels[depth].insert(policy, id);
        self.childless.insert(id);
        Ok(id)
    }

    pub(super) fn delete_node(&mut self, id: NodeId) {
        let mut pending = vec![id];
        while let Some(id) = pending.pop() {
            let Some(mut node) = self.nodes.remove(&id) else {
                continue;
            };
            self.levels[node.depth].remove(&node.policy);
            self.childless.remove(&id);
            for parent in &node.parents {
                if let Some(parent_node) = self.nodes.get_mut(parent) {
                    parent_node.children.remove(&id);
                    if parent_node.children.is_empty() {
                        self.childless.insert(*parent);
                    }
                }
            }
            for child in &node.children {
                if let Some(child_node) = self.nodes.get_mut(child) {
                    child_node.parents.remove(&id);
                    if child_node.parents.is_empty() {
                        pending.push(*child);
                    }
                }
            }
            node.parents.clear();
            node.children.clear();
            #[cfg(test)]
            self.detached.insert(id, node);
        }
    }

    pub(super) fn prune(&mut self, max_depth: usize) -> bool {
        #[cfg(test)]
        self.prune_calls.push(max_depth);
        let mut pending: Vec<_> = self
            .childless
            .iter()
            .copied()
            .filter(|id| self.node(*id).depth <= max_depth)
            .collect();
        while let Some(id) = pending.pop() {
            let Some(node) = self.nodes.get(&id) else {
                continue;
            };
            let parents: Vec<_> = node.parents.iter().copied().collect();
            self.delete_node(id);
            pending.extend(parents.into_iter().filter(|id| self.childless.contains(id)));
        }
        !self.levels[0].is_empty()
    }

    fn reachable(&self, id: NodeId, parents: bool) -> Vec<NodeId> {
        let edges = |id| {
            if parents {
                &self.node(id).parents
            } else {
                &self.node(id).children
            }
        };
        let mut seen = BTreeSet::new();
        let mut pending: Vec<_> = edges(id).iter().copied().collect();
        while let Some(id) = pending.pop() {
            if seen.insert(id) {
                pending.extend(edges(id).iter().copied());
            }
        }
        seen.into_iter().collect()
    }
    pub(super) fn ancestors(&self, id: NodeId) -> Vec<NodeId> {
        self.reachable(id, true)
    }
    pub(super) fn descendants(&self, id: NodeId) -> Vec<NodeId> {
        self.reachable(id, false)
    }
}

pub(super) fn update(
    graph: &mut Graph,
    depth: usize,
    policies: &[PolicyInformation],
    any_allowed: bool,
) -> Result<bool, GraphError> {
    let mut expected: BTreeMap<ObjectIdentifier, Vec<NodeId>> = BTreeMap::new();
    for id in graph.nodes_at_depth(depth as isize - 1) {
        for oid in &graph.node(id).expected {
            expected.entry(*oid).or_default().push(id);
        }
    }
    let mut wildcard = None;
    for policy in policies {
        let oid = policy.policy_identifier;
        if oid == ANY {
            wildcard = Some(policy);
            continue;
        }
        if graph.node_at(depth as isize, oid).is_some() {
            continue;
        }
        let parents = match expected.get(&oid) {
            Some(ids) => ids.clone(),
            None => match graph.node_at(depth as isize - 1, ANY) {
                Some(id) => vec![id],
                None => continue,
            },
        };
        graph.add_node(
            depth,
            oid,
            policy.policy_qualifiers.clone().unwrap_or_default(),
            BTreeSet::from([oid]),
            &parents,
        )?;
    }
    if let Some(policy) = wildcard.filter(|_| any_allowed) {
        for (oid, parents) in expected {
            if graph.node_at(depth as isize, oid).is_none() {
                graph.add_node(
                    depth,
                    oid,
                    policy.policy_qualifiers.clone().unwrap_or_default(),
                    BTreeSet::from([oid]),
                    &parents,
                )?;
            }
        }
    }
    Ok(graph.prune(depth - 1))
}

pub(super) fn apply_mapping(
    graph: &mut Graph,
    depth: usize,
    mappings: &BTreeMap<ObjectIdentifier, BTreeSet<ObjectIdentifier>>,
    mapping_allowed: bool,
) -> Result<bool, GraphError> {
    for (issuer, subjects) in mappings {
        let node = graph.node_at(depth as isize, *issuer);
        if mapping_allowed {
            if let Some(id) = node {
                graph
                    .node_mut(id)
                    .ok_or(GraphError::UnknownNode(id))?
                    .expected = subjects.clone();
            } else if let Some(id) = graph.node_at(depth as isize, ANY) {
                let node = graph.node(id);
                let qualifiers = node.qualifiers.clone();
                let parents: Vec<_> = node.parents.iter().copied().collect();
                graph.add_node(depth, *issuer, qualifiers, subjects.clone(), &parents)?;
            }
        } else if let Some(id) = node {
            graph.delete_node(id);
        }
    }
    Ok(graph.prune(depth - 1))
}

pub(super) struct AuthorityPolicy {
    pub(super) qualifiers: Vec<PolicyQualifierInfo>,
    pub(super) issuer_policies: BTreeSet<ObjectIdentifier>,
}

pub(super) fn authority_constrained(
    graph: Option<&Graph>,
    path_length: usize,
) -> BTreeMap<ObjectIdentifier, AuthorityPolicy> {
    let Some(graph) = graph else {
        return BTreeMap::new();
    };
    let mut candidates = Vec::new();
    for depth in 1..=path_length.min(graph.depth()) {
        for id in graph.nodes_at_depth(depth as isize) {
            let node = graph.node(id);
            if node.policy != ANY
                && node.parents.len() == 1
                && node
                    .parents
                    .first()
                    .is_some_and(|parent| graph.node(*parent).policy == ANY)
            {
                candidates.push(id);
            }
        }
    }
    if let Some(id) = graph.node_at(path_length as isize, ANY) {
        candidates.push(id);
    }
    let mut result = BTreeMap::<_, AuthorityPolicy>::new();
    for id in candidates {
        let node = graph.node(id);
        let value = result
            .entry(node.policy)
            .or_insert_with(|| AuthorityPolicy {
                qualifiers: Vec::new(),
                issuer_policies: BTreeSet::new(),
            });
        let descendants = graph.descendants(id);
        let relatives = std::iter::once(id)
            .chain(graph.ancestors(id))
            .chain(descendants.iter().copied());
        for relative in relatives {
            for qualifier in &graph.node(relative).qualifiers {
                if !value.qualifiers.contains(qualifier) {
                    value.qualifiers.push(qualifier.clone());
                }
            }
        }
        if node.depth == path_length {
            value.issuer_policies.insert(node.policy);
        }
        for descendant in descendants {
            let node = graph.node(descendant);
            if node.depth == path_length {
                value.issuer_policies.insert(node.policy);
            }
        }
    }
    result
}

pub(super) fn user_constrained(
    graph: Option<&Graph>,
    path_length: usize,
    acceptable: &BTreeSet<ObjectIdentifier>,
) -> Vec<QualifiedPolicy> {
    let authority = authority_constrained(graph, path_length);
    let mut result: Vec<_> = authority
        .iter()
        .filter(|(oid, _)| acceptable.contains(&ANY) || acceptable.contains(*oid))
        .flat_map(|(oid, policy)| {
            policy.issuer_policies.iter().map(|issuer| QualifiedPolicy {
                user_domain_policy_id: *oid,
                issuer_domain_policy_id: *issuer,
                qualifiers: policy.qualifiers.clone(),
            })
        })
        .collect();
    if !acceptable.contains(&ANY) {
        if let Some(wildcard) = authority.get(&ANY) {
            let accounted: BTreeSet<_> = result.iter().map(|p| p.user_domain_policy_id).collect();
            result.extend(
                acceptable
                    .difference(&accounted)
                    .map(|oid| QualifiedPolicy {
                        user_domain_policy_id: *oid,
                        issuer_domain_policy_id: *oid,
                        qualifiers: wildcard.qualifiers.clone(),
                    }),
            );
        }
    }
    result
}

fn failure(
    path: &crate::path::ValidationPath,
    index: usize,
    total: usize,
    error: sigis_pki_core::errors::ValidationError,
) -> Box<super::PathFailure> {
    let mut failure = super::PathFailure::plain(error, Some(path.clone()));
    failure.is_ee_cert = index + 1 == total && path.leaf().is_some();
    Box::new(failure)
}

// RFC 5280 policy state updates, with the RFC 9618 graph. The caller keeps
// certval's complete validation mandatory; this result cannot override it.
pub(super) fn process_path(
    path: &crate::path::ValidationPath,
    params: Option<&crate::policy::PkixValidationParams>,
    empty_intersection: bool,
) -> Result<Vec<QualifiedPolicy>, Box<super::PathFailure>> {
    use sigis_pki_core::errors::ValidationError;
    use x509_cert::ext::pkix::{
        CertificatePolicies, InhibitAnyPolicy, PolicyConstraints, PolicyMappings,
    };

    let defaults = crate::policy::PkixValidationParams::default();
    let params = params.unwrap_or(&defaults);
    let issued = path.issued_certs();
    let total = issued.len();
    let mut graph = Graph::new(params.max_policy_graph_nodes);
    let mut alive = true;
    let initial_counter = total.saturating_add(1);
    let mut explicit = if params.initial_explicit_policy {
        0
    } else {
        initial_counter
    };
    let mut inhibit_any = if params.initial_any_policy_inhibit {
        0
    } else {
        initial_counter
    };
    let mut mapping = if params.initial_policy_mapping_inhibit {
        0
    } else {
        initial_counter
    };
    let acceptable: BTreeSet<_> = if empty_intersection {
        BTreeSet::new()
    } else if params.user_initial_policy_set.is_empty() {
        BTreeSet::from([ANY])
    } else {
        params.user_initial_policy_set.iter().copied().collect()
    };

    for (index, (cert, _)) in issued.iter().enumerate() {
        let depth = index + 1;
        let description = path.describe(index, total);
        let fail = |error| failure(path, index, total, error);
        let graph_error = |error| {
            let error = match error {
                GraphError::SizeLimit(_) => ValidationError::PathValidation(format!(
                    "The path could not be validated because policy processing for {description} exceeds the size limit on the policy graph"
                )),
                error => ValidationError::PathValidation(error.to_string()),
            };
            fail(error)
        };
        match cert.extension::<CertificatePolicies>().map_err(fail)? {
            None => alive = false,
            Some((_, policies)) if alive => {
                alive = update(
                    &mut graph,
                    depth,
                    &policies.0,
                    inhibit_any > 0 || (depth < total && cert.is_self_issued()),
                )
                .map_err(graph_error)?;
            }
            _ => {}
        }
        if !alive && explicit == 0 {
            return Err(fail(ValidationError::PathValidation(format!(
                "The path could not be validated because there is no valid set of policies for {description}"
            ))));
        }
        let constraints = cert
            .extension::<PolicyConstraints>()
            .map_err(fail)?
            .map(|(_, c)| c);
        if depth < total {
            if let Some((_, mappings)) = cert.extension::<PolicyMappings>().map_err(fail)? {
                let mut map = BTreeMap::<_, BTreeSet<_>>::new();
                for pair in mappings.0 {
                    // This check is mandatory even after the graph became NULL.
                    if pair.issuer_domain_policy == ANY || pair.subject_domain_policy == ANY {
                        return Err(fail(ValidationError::PathValidation(format!(
                            "The path could not be validated because {description} contains a policy mapping for the \"any policy\""
                        ))));
                    }
                    map.entry(pair.issuer_domain_policy)
                        .or_default()
                        .insert(pair.subject_domain_policy);
                }
                if alive && !map.is_empty() {
                    alive =
                        apply_mapping(&mut graph, depth, &map, mapping > 0).map_err(graph_error)?;
                }
            }
            if !cert.is_self_issued() {
                explicit = explicit.saturating_sub(1);
                mapping = mapping.saturating_sub(1);
                inhibit_any = inhibit_any.saturating_sub(1);
            }
            if let Some(constraints) = constraints {
                if let Some(limit) = constraints.require_explicit_policy {
                    explicit = explicit.min(limit as usize);
                }
                if let Some(limit) = constraints.inhibit_policy_mapping {
                    mapping = mapping.min(limit as usize);
                }
            }
            if let Some((_, limit)) = cert.extension::<InhibitAnyPolicy>().map_err(fail)? {
                inhibit_any = inhibit_any.min(limit.0 as usize);
            }
        } else {
            // Final wrap-up decrements even for a self-issued target.
            explicit = explicit.saturating_sub(1);
            if constraints.and_then(|c| c.require_explicit_policy) == Some(0) {
                explicit = 0;
            }
        }
    }
    let policies = user_constrained(alive.then_some(&graph), total, &acceptable);
    if policies.is_empty() && explicit == 0 {
        let index = total.saturating_sub(1);
        let description = path.describe(index, total);
        return Err(failure(path, index, total, ValidationError::PathValidation(format!(
            "The path could not be validated because there is no valid set of policies for {description}."
        ))));
    }
    Ok(policies)
}
