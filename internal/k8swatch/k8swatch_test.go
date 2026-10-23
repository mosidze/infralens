package k8swatch

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"infralens/internal/engine"
	"infralens/internal/watch"
)

var now = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

func ago2(d time.Duration) metav1.Time { return metav1.NewTime(now.Add(-d)) }

func cluster(objs ...runtime.Object) *Cluster {
	return &Cluster{Client: fake.NewSimpleClientset(objs...), Now: func() time.Time { return now }}
}

func env() *watch.Env { return &watch.Env{Now: now} }

func ctl(kind, name string) []metav1.OwnerReference {
	t := true
	return []metav1.OwnerReference{{Kind: kind, Name: name, Controller: &t}}
}

func deployment(ns, name string, desired, available int32, conds ...appsv1.DeploymentCondition) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       appsv1.DeploymentSpec{Replicas: &desired},
		Status:     appsv1.DeploymentStatus{AvailableReplicas: available, Conditions: conds},
	}
}

func rs(ns, name, dep string) *appsv1.ReplicaSet {
	return &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, OwnerReferences: ctl("Deployment", dep)}}
}

func pod(ns, name, owner, ownerKind string, st corev1.PodStatus, age time.Duration) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(ns + name), CreationTimestamp: ago2(age),
		OwnerReferences: ctl(ownerKind, owner), Labels: map[string]string{"app": "x"}}, Status: st}
}

func waiting(reason, msg string) corev1.PodStatus {
	return corev1.PodStatus{Phase: corev1.PodPending, ContainerStatuses: []corev1.ContainerStatus{{Name: "c",
		State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reason, Message: msg}}}}}
}

func byNode(obs []watch.Observation) map[string]watch.Observation {
	m := map[string]watch.Observation{}
	for _, o := range obs {
		m[o.NodeID+"|"+o.Kind] = o
	}
	return m
}

func TestDeploymentsAreJudgedByReadyReplicasNotByPods(t *testing.T) {
	down := deployment("biz-staging", "vehicles", 1, 0, appsv1.DeploymentCondition{Type: "Available", Status: corev1.ConditionFalse, LastTransitionTime: ago2(70 * 24 * time.Hour)})
	prodDown := deployment("shop", "checkout", 3, 1, appsv1.DeploymentCondition{Type: "Available", Status: corev1.ConditionFalse, LastTransitionTime: ago2(20 * time.Minute)})
	healthy := deployment("shop", "catalog", 2, 2)
	scaledOff := deployment("shop", "legacy", 0, 0)
	rolling := deployment("shop", "search", 3, 2, appsv1.DeploymentCondition{Type: "Progressing", Status: corev1.ConditionTrue, Reason: "ReplicaSetUpdated", LastUpdateTime: ago2(time.Minute)})
	stuck := deployment("shop", "export", 1, 0, appsv1.DeploymentCondition{Type: "Progressing", Status: corev1.ConditionFalse, Reason: "ProgressDeadlineExceeded"})
	c := cluster(down, prodDown, healthy, scaledOff, rolling, stuck,
		rs("biz-staging", "vehicles-5f", "vehicles"),
		pod("biz-staging", "vehicles-5f-a", "vehicles-5f", "ReplicaSet", waiting("ImagePullBackOff", "Back-off pulling image \"reg/x:v9\""), time.Hour),
		pod("shop", "catalog-aaa", "x", "ReplicaSet", corev1.PodStatus{Phase: corev1.PodRunning}, time.Hour),
	)
	obs, err := (&workloads{c}).Collect(context.Background(), env())
	if err != nil {
		t.Fatal(err)
	}
	m := byNode(obs)
	if len(m) != 3 {
		t.Fatalf("only vehicles, checkout and export are problems, got %d: %v", len(m), obs)
	}
	v := m["biz-staging/Deployment/vehicles|k8s.workload-unavailable"]
	if v.Severity != watch.SevWarn {
		t.Fatalf("no replicas in a staging namespace must not be critical: %v", v.Severity)
	}
	if !strings.Contains(strings.Join(v.Evidence, " "), "ImagePullBackOff") || v.Since.IsZero() {
		t.Fatalf("evidence and start: %+v", v)
	}
	if o := m["shop/Deployment/checkout|k8s.workload-unavailable"]; o.Severity != watch.SevWarn || o.Title != "1 of 3 replicas ready" {
		t.Fatalf("partial: %+v", o)
	}
	if o := m["shop/Deployment/export|k8s.workload-unavailable"]; o.Severity != watch.SevCrit || !strings.Contains(strings.Join(o.Evidence, " "), "progress deadline") {
		t.Fatalf("stuck rollout: %+v", o)
	}
}

func TestSystemNamespacesAreAlwaysCriticalAndStagingNeverIs(t *testing.T) {
	if sev("kube-system", watch.SevWarn) != watch.SevCrit {
		t.Fatal("cluster plumbing must be critical")
	}
	if sev("biz-staging", watch.SevCrit) != watch.SevWarn || sev("shop-dev", watch.SevCrit) != watch.SevWarn {
		t.Fatal("non-prod must be downgraded")
	}
	if sev("shop", watch.SevCrit) != watch.SevCrit || sev("shop", watch.SevWarn) != watch.SevWarn {
		t.Fatal("prod keeps its severity")
	}
}

func crashPod(ns, name, owner string, restarts int32, age time.Duration) *corev1.Pod {
	return pod(ns, name, owner, "ReplicaSet", corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
		Name: "app", RestartCount: restarts,
		State:                corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
		LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Error", ExitCode: 1, FinishedAt: ago2(3 * time.Minute)}},
	}}}, age)
}

func TestRestartsAreJudgedByRateAndAnOldBrokenPodIsStanding(t *testing.T) {
	steady := pod("shop", "steady-1", "steady-rs", "ReplicaSet", corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
		Name: "app", RestartCount: 161, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}, 90*24*time.Hour)
	c := cluster(
		rs("shop", "steady-rs", "steady"), rs("shop", "fresh-rs", "fresh"), rs("bad-dev", "doccy-rs", "doccy"),
		steady,
		crashPod("shop", "fresh-1", "fresh-rs", 6, 40*time.Minute),
		crashPod("bad-dev", "doccy-1", "doccy-rs", 21293, 150*24*time.Hour),
	)
	r := &restarts{c: c}
	obs, err := r.Collect(context.Background(), env())
	if err != nil {
		t.Fatal(err)
	}
	m := byNode(obs)
	if _, ok := m["shop/Deployment/steady|k8s.restarting"]; ok {
		t.Fatal("161 restarts over three months with none lately is not a problem now")
	}
	fresh := m["shop/Deployment/fresh|k8s.restarting"]
	if fresh.Severity != watch.SevCrit || fresh.Chronic {
		t.Fatalf("a new restart loop in prod is critical and fresh: %+v", fresh)
	}
	old := m["bad-dev/Deployment/doccy|k8s.restarting"]
	if !old.Chronic || !strings.Contains(strings.Join(old.Evidence, " "), "150 days") {
		t.Fatalf("a pod that has crashed 21,293 times over 150 days is standing: %+v", old)
	}

	// a healthy-looking pod that starts restarting is caught by the rate
	c2 := cluster(rs("shop", "flaky-rs", "flaky"), pod("shop", "flaky-1", "flaky-rs", "ReplicaSet", corev1.PodStatus{Phase: corev1.PodRunning,
		ContainerStatuses: []corev1.ContainerStatus{{Name: "app", RestartCount: 10, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}, time.Hour))
	r2 := &restarts{c: c2}
	if got, _ := r2.Collect(context.Background(), env()); len(got) != 0 {
		t.Fatalf("the first poll has nothing to compare with: %v", got)
	}
	c2.Client.(*fake.Clientset).Tracker().Update(corev1.SchemeGroupVersion.WithResource("pods"), pod("shop", "flaky-1", "flaky-rs", "ReplicaSet", corev1.PodStatus{Phase: corev1.PodRunning,
		ContainerStatuses: []corev1.ContainerStatus{{Name: "app", RestartCount: 15, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}, time.Hour), "shop")
	c2.cache = nil // let the next poll see the change
	got, _ := r2.Collect(context.Background(), env())
	if len(got) != 1 || got[0].Severity != watch.SevWarn || !strings.Contains(got[0].Title, "5 times") {
		t.Fatalf("5 restarts since the last look: %+v", got)
	}
}

func TestOOMKillsOfOneOffJobsAreOneProblemNotThirtyFive(t *testing.T) {
	oom := func(name string, finished time.Duration) *corev1.Pod {
		return pod("aaa-dashboard", name, "run-"+name, "Job", corev1.PodStatus{Phase: corev1.PodFailed, ContainerStatuses: []corev1.ContainerStatus{{
			Name: "flow", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled", ExitCode: 137, FinishedAt: ago2(finished)}}}}}, 5*time.Hour)
	}
	var objs []runtime.Object
	for _, n := range []string{"a", "b", "c", "d"} {
		p := oom(n, 2*time.Hour)
		p.Spec.Containers = []corev1.Container{{Name: "flow", Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("512Mi")}}}}
		objs = append(objs, p)
	}
	objs = append(objs, oom("old", 9*time.Hour))
	obs, err := (&restarts{c: cluster(objs...)}).Collect(context.Background(), env())
	if err != nil {
		t.Fatal(err)
	}
	var ooms []watch.Observation
	for _, o := range obs {
		if o.Kind == "k8s.oom-killed" {
			ooms = append(ooms, o)
		}
	}
	if len(ooms) != 1 {
		t.Fatalf("one-off jobs are bucketed per namespace: %d signals", len(ooms))
	}
	o := ooms[0]
	if o.NodeID != "aaa-dashboard/Jobs/one-off jobs" || !strings.Contains(o.Title, "4 container(s)") || o.Severity != watch.SevCrit {
		t.Fatalf("%+v", o)
	}
	if !strings.Contains(strings.Join(o.Evidence, " "), "memory limit 512Mi") {
		t.Fatalf("the limit is the first thing to look at: %v", o.Evidence)
	}
}

func node(name string, ready corev1.ConditionStatus, cp bool, extra ...corev1.NodeCondition) *corev1.Node {
	n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{}}}
	if cp {
		n.Labels["node-role.kubernetes.io/control-plane"] = ""
	}
	n.Status.Conditions = append([]corev1.NodeCondition{{Type: corev1.NodeReady, Status: ready, LastTransitionTime: ago2(10 * time.Minute), Message: "kubelet stopped posting status"}}, extra...)
	return n
}

func TestNodesAndControlPlaneQuorum(t *testing.T) {
	c := cluster(
		node("w1", corev1.ConditionTrue, false),
		node("w2", corev1.ConditionFalse, false),
		node("w3", corev1.ConditionTrue, false, corev1.NodeCondition{Type: corev1.NodeDiskPressure, Status: corev1.ConditionTrue}),
		node("cp1", corev1.ConditionTrue, true), node("cp2", corev1.ConditionTrue, true), node("cp3", corev1.ConditionTrue, true),
		node("cp4", corev1.ConditionFalse, true), node("cp5", corev1.ConditionFalse, true),
	)
	obs, _ := (&nodes{c}).Collect(context.Background(), env())
	m := byNode(obs)
	if o := m["node/w2|k8s.node-not-ready"]; o.Severity != watch.SevCrit {
		t.Fatalf("not ready: %+v", o)
	}
	if _, ok := m["node/w1|k8s.node-not-ready"]; ok {
		t.Fatal("a ready node is not a problem")
	}
	if _, ok := m["node/w3|k8s.node-pressure"]; !ok {
		t.Fatal("disk pressure")
	}
	q := m["|k8s.quorum-at-risk"]
	if q.Severity != watch.SevWarn || !strings.Contains(q.Title, "3 of 5") {
		t.Fatalf("3 of 5 control-plane nodes is a bare majority: %+v", q)
	}
	// lose another and quorum is gone
	c2 := cluster(node("cp1", corev1.ConditionTrue, true), node("cp2", corev1.ConditionTrue, true), node("cp3", corev1.ConditionFalse, true),
		node("cp4", corev1.ConditionFalse, true), node("cp5", corev1.ConditionFalse, true))
	obs, _ = (&nodes{c2}).Collect(context.Background(), env())
	if o := byNode(obs)["|k8s.quorum-lost"]; o.Severity != watch.SevCrit {
		t.Fatalf("quorum lost: %+v", obs)
	}
}

func ready(b bool) *bool { return &b }

func TestServicesWithNothingReadyBehindThemAreFlaggedByHowExposedTheyAre(t *testing.T) {
	svc := func(ns, name string, sel map[string]string, typ corev1.ServiceType) *corev1.Service {
		return &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: corev1.ServiceSpec{Selector: sel, Type: typ}}
	}
	slice := func(ns, svcName string, ok bool) *discoveryv1.EndpointSlice {
		return &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: svcName + "-x", Labels: map[string]string{"kubernetes.io/service-name": svcName}},
			Endpoints: []discoveryv1.Endpoint{{Conditions: discoveryv1.EndpointConditions{Ready: ready(ok)}}}}
	}
	pathType := networkingv1.PathTypePrefix
	ing := &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web"}, Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{
		IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{
			Path: "/", PathType: &pathType, Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "front"}}}}}}}}}}
	c := cluster(
		svc("shop", "front", map[string]string{"app": "front"}, corev1.ServiceTypeClusterIP), slice("shop", "front", false),
		svc("shop", "internal", map[string]string{"app": "x"}, corev1.ServiceTypeClusterIP), slice("shop", "internal", false),
		svc("shop", "idle", map[string]string{"app": "nobody"}, corev1.ServiceTypeClusterIP),
		svc("shop", "fine", map[string]string{"app": "x"}, corev1.ServiceTypeClusterIP), slice("shop", "fine", true),
		svc("shop", "external", nil, corev1.ServiceTypeExternalName),
		ing,
		pod("shop", "internal-1", "x", "ReplicaSet", waiting("CrashLoopBackOff", ""), time.Hour),
	)
	obs, err := (&services{c}).Collect(context.Background(), env())
	if err != nil {
		t.Fatal(err)
	}
	m := byNode(obs)
	if len(m) != 2 {
		t.Fatalf("front (public, nothing behind) and internal (pods, none ready): %d %v", len(m), obs)
	}
	if o := m["shop/Service/front|k8s.service-no-endpoints"]; o.Severity != watch.SevCrit {
		t.Fatalf("a service behind an ingress with nothing behind it is the clearest sign of an outage: %+v", o)
	}
	if o := m["shop/Service/internal|k8s.service-no-endpoints"]; o.Severity != watch.SevWarn || !strings.Contains(strings.Join(o.Evidence, " "), "CrashLoopBackOff") {
		t.Fatalf("internal: %+v", o)
	}
}

func TestFailedJobsAreGroupedAndOldOnesIgnored(t *testing.T) {
	failedJob := func(ns, name string, owner []metav1.OwnerReference, age time.Duration) *batchv1.Job {
		return &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, OwnerReferences: owner},
			Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{{Type: "Failed", Status: corev1.ConditionTrue, Reason: "BackoffLimitExceeded", LastTransitionTime: ago2(age)}}}}
	}
	c := cluster(
		failedJob("data", "nightly-1", ctl("CronJob", "nightly"), 2*time.Hour),
		failedJob("data", "nightly-2", ctl("CronJob", "nightly"), 20*time.Hour),
		failedJob("data", "nightly-0", ctl("CronJob", "nightly"), 5*24*time.Hour),
		failedJob("data", "adhoc", nil, time.Hour),
	)
	obs, _ := (&jobsC{c}).Collect(context.Background(), env())
	m := byNode(obs)
	if len(m) != 2 {
		t.Fatalf("%d: %v", len(m), obs)
	}
	if o := m["data/CronJob/nightly|k8s.jobs-failed"]; !strings.Contains(o.Title, "2 job(s)") {
		t.Fatalf("the five-day-old failure is history: %+v", o)
	}
}

func TestStorageProblemsAndOnlyTheEventsThatMatter(t *testing.T) {
	ev := func(reason, obj, kind string, age time.Duration) *corev1.Event {
		return &corev1.Event{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: reason + obj + age.String()}, Type: "Warning", Reason: reason, Message: reason + " detail",
			InvolvedObject: corev1.ObjectReference{Kind: kind, Namespace: "shop", Name: obj}, LastTimestamp: ago2(age)}
	}
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "data", CreationTimestamp: ago2(time.Hour)}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}}
	fresh := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "new", CreationTimestamp: ago2(time.Minute)}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}}
	c := cluster(pvc, fresh, rs("shop", "db-rs", "db"),
		pod("shop", "db-1", "db-rs", "ReplicaSet", corev1.PodStatus{Phase: corev1.PodPending}, time.Hour),
		ev("FailedMount", "db-1", "Pod", 3*time.Minute),
		ev("FailedMount", "db-1", "Pod", 2*time.Minute),
		ev("FailedMount", "db-1", "Pod", 3*time.Hour), // too old
		ev("PolicyViolation", "require-limits", "ClusterPolicy", time.Minute),
		ev("BackOff", "db-1", "Pod", time.Minute),
	)
	obs, _ := (&storage{c}).Collect(context.Background(), env())
	m := byNode(obs)
	if len(m) != 2 {
		t.Fatalf("a pending claim and one grouped mount failure; policy events and back-offs are not storage: %d %v", len(m), obs)
	}
	if _, ok := m["shop/PersistentVolumeClaim/data|k8s.pvc-pending"]; !ok {
		t.Fatal("old pending claim")
	}
	if o := m["shop/Deployment/db|k8s.failedmount"]; o.Title != "a volume cannot be mounted" {
		t.Fatalf("events are attributed to the workload that owns the pod: %v", obs)
	}
}

func TestTheTransportRefusesEverythingButReads(t *testing.T) {
	c := &Counter{}
	var seen []string
	next := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		seen = append(seen, r.Method)
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	})
	rt := readOnly{next: next, c: c}
	for _, m := range []string{"GET", "HEAD"} {
		req, _ := http.NewRequest(m, "https://k8s/api/v1/pods", nil)
		if _, err := rt.RoundTrip(req); err != nil {
			t.Fatalf("%s must pass: %v", m, err)
		}
	}
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		req, _ := http.NewRequest(m, "https://k8s/api/v1/namespaces/x/pods", nil)
		if _, err := rt.RoundTrip(req); err == nil || !strings.Contains(err.Error(), "never changes a cluster") {
			t.Fatalf("%s must be refused: %v", m, err)
		}
	}
	if calls, blocked := c.Counts(); calls != 2 || blocked != 4 || len(seen) != 2 {
		t.Fatalf("calls %d blocked %d reached %v", calls, blocked, seen)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGraphConnectsIngressServiceAndWorkload(t *testing.T) {
	pathType := networkingv1.PathTypePrefix
	c := cluster(
		deployment("shop", "front", 2, 2), rs("shop", "front-rs", "front"),
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "front-1", Labels: map[string]string{"app": "front"}, OwnerReferences: ctl("ReplicaSet", "front-rs")}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "front"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "front"}}},
		&networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web"}, Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{PathType: &pathType,
				Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "front"}}}}}}}}}},
	)
	res, err := BuildGraph(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	g := watch.NewGraph(res)
	if _, ok := g.Resolve("shop/Deployment/front"); !ok {
		t.Fatal("deployment missing from the graph")
	}
	edges := map[string]bool{}
	for _, e := range res.Edges {
		edges[e.Source+">"+e.Target] = true
	}
	if !edges["shop/Service/front>shop/Deployment/front"] || !edges["shop/Ingress/web>shop/Service/front"] {
		t.Fatalf("edges: %v", edges)
	}
}

func TestARunnerOverTheseCollectorsTurnsASickClusterIntoOneIncident(t *testing.T) {
	c := cluster(
		deployment("shop", "front", 2, 0, appsv1.DeploymentCondition{Type: "Available", Status: corev1.ConditionFalse, LastTransitionTime: ago2(10 * time.Minute)}),
		rs("shop", "front-rs", "front"),
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "front-1", Labels: map[string]string{"app": "front"}, OwnerReferences: ctl("ReplicaSet", "front-rs")}, Status: waiting("ImagePullBackOff", "")},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "front"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "front"}, Type: corev1.ServiceTypeLoadBalancer}},
	)
	res, _ := BuildGraph(context.Background(), c)
	r := &watch.Runner{Collectors: Collectors(c), Tracker: watch.NewTracker(1, 1), Graph: watch.NewGraph(res), Now: func() time.Time { return now }}
	r.PollOnce(context.Background())
	snap := r.Snapshot()
	if len(snap.Incidents) != 1 || len(snap.Incidents[0].Nodes) != 2 {
		t.Fatalf("the workload and the service in front of it are one incident: %+v", snap.Incidents)
	}
	if snap.Crit != 2 {
		t.Fatalf("crit=%d", snap.Crit)
	}
}

func TestAServiceInFrontOfALongBrokenWorkloadIsAsOldAsTheWorkload(t *testing.T) {
	c := cluster(
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "biz-staging", Name: "vehicles"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "x"}}},
		pod("biz-staging", "vehicles-1", "x", "ReplicaSet", waiting("ImagePullBackOff", ""), 70*24*time.Hour),
	)
	obs, _ := (&services{c}).Collect(context.Background(), env())
	if len(obs) != 1 || now.Sub(obs[0].Since) < 60*24*time.Hour {
		t.Fatalf("the signal must carry the age of what is behind it: %+v", obs)
	}
	r := &watch.Runner{Collectors: []watch.Collector{&services{c}}, Tracker: watch.NewTracker(1, 1), Graph: watch.NewGraph(engine0()), Now: func() time.Time { return now }}
	r.PollOnce(context.Background())
	snap := r.Snapshot()
	if len(snap.Incidents) != 0 || len(snap.Chronic) != 1 {
		t.Fatalf("a 70-day-old problem is standing, not a fire: %+v", snap)
	}
}

func engine0() engine.ScanResult { return engine.ScanResult{} }

func TestTheRoleGrantsReadsOnlyAndNoSecrets(t *testing.T) {
	for _, bad := range []string{"create", "update", "patch", "delete", "deletecollection", "secrets", "configmaps", "*", "exec", "proxy"} {
		for _, line := range strings.Split(RBAC, "\n") {
			if strings.Contains(line, "verbs:") || strings.Contains(line, "resources:") {
				for _, w := range strings.FieldsFunc(line, func(r rune) bool { return r == '[' || r == ']' || r == ',' || r == ' ' || r == ':' }) {
					if w == bad {
						t.Fatalf("the role must not mention %q: %s", bad, line)
					}
				}
			}
		}
	}
}
