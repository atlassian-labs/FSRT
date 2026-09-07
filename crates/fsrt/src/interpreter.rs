use std::collections::HashMap;

use forge_analyzer::{
    definitions::Environment,
    interp::{Interp, Runner},
};
use forge_permission_resolver::{
    permissions_cache::CacheConfig,
    permissions_resolver::{
        PermissionHashMap, get_permission_resolver_bitbucket, get_permission_resolver_compass,
        get_permission_resolver_confluence, get_permission_resolver_jira,
        get_permission_resolver_jira_any, get_permission_resolver_jira_service_management,
        get_permission_resolver_jira_software,
    },
    permissions_resolver_compass::CompassPermissionResolver,
};
use regex::Regex;

type RestPermissions = (PermissionHashMap, HashMap<String, Regex>);

#[derive(Default)]
struct PermissionResolvers {
    jira_any: RestPermissions,
    jira_software: RestPermissions,
    jira_service_management: RestPermissions,
    jira: RestPermissions,
    confluence: RestPermissions,
    bitbucket: RestPermissions,
    compass: CompassPermissionResolver,
}

impl PermissionResolvers {
    fn load(config: &CacheConfig) -> Self {
        Self {
            jira_any: get_permission_resolver_jira_any(config),
            jira_software: get_permission_resolver_jira_software(config),
            jira_service_management: get_permission_resolver_jira_service_management(config),
            jira: get_permission_resolver_jira(config),
            confluence: get_permission_resolver_confluence(config),
            bitbucket: get_permission_resolver_bitbucket(config),
            compass: get_permission_resolver_compass(),
        }
    }
}

/// Shared inputs for interpreters, each of which keeps its own checker state.
pub(crate) struct InterpreterFactory<'env> {
    env: &'env Environment,
    permissions: Vec<String>,
    resolvers: PermissionResolvers,
}

impl<'env> InterpreterFactory<'env> {
    pub(crate) fn new(
        env: &'env Environment,
        permissions: Vec<String>,
        permission_cache: Option<&CacheConfig>,
    ) -> Self {
        Self {
            env,
            permissions,
            resolvers: permission_cache
                .map(PermissionResolvers::load)
                .unwrap_or_default(),
        }
    }

    pub(crate) fn create<'cx, C: Runner<'cx>>(&'cx self, call_uncalled: bool) -> Interp<'cx, C> {
        let resolvers = &self.resolvers;
        Interp::new(
            self.env,
            false,
            call_uncalled,
            self.permissions.clone(),
            &resolvers.jira_any.0,
            &resolvers.jira_any.1,
            &resolvers.jira_software.0,
            &resolvers.jira_software.1,
            &resolvers.jira_service_management.0,
            &resolvers.jira_service_management.1,
            &resolvers.jira.0,
            &resolvers.jira.1,
            &resolvers.confluence.0,
            &resolvers.confluence.1,
            &resolvers.bitbucket.0,
            &resolvers.bitbucket.1,
            &resolvers.compass,
        )
    }
}
