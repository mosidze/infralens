package k8swatch

// RBAC is the read-only ClusterRole the monitor needs. It lists, gets and
// watches; it cannot create, change or delete anything, and it has no access
// to Secrets or ConfigMaps. The transport enforces the same limit on the
// client side.
const RBAC = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: infralens-readonly
rules:
  - apiGroups: [""]
    resources: [pods, services, nodes, persistentvolumeclaims, events]
    verbs: [get, list, watch]
  - apiGroups: ["apps"]
    resources: [deployments, replicasets, statefulsets, daemonsets]
    verbs: [get, list, watch]
  - apiGroups: ["batch"]
    resources: [jobs, cronjobs]
    verbs: [get, list, watch]
  - apiGroups: ["discovery.k8s.io"]
    resources: [endpointslices]
    verbs: [get, list, watch]
  - apiGroups: ["networking.k8s.io"]
    resources: [ingresses]
    verbs: [get, list, watch]
  - apiGroups: ["autoscaling"]
    resources: [horizontalpodautoscalers]
    verbs: [get, list, watch]
`
