/**
 * Tray: an empty tray balanced on a pin over a plinth, for the report's empty
 * states. The pointer is projected onto the ground and the tray tips toward
 * it, each axis on its own spring, by up to the slider's angle. At rest it
 * leans a little toward its near corner, and one punched dot on its floor
 * says where to look; when the pointer leans it, the rim takes the bright
 * stroke instead. The read-out names the corner it tips toward.
 *
 * Built on the Hairline kernel (MIT, @lucasmarkes/hairline), in its figure
 * format: cloudg's report mounts it through a small hairline() host.
 */
const {
  Cam, clamp, facing, fit, hull, open, poly, proj, rad, ringAt, rings, run, unproj,
  spring, stepS, flatDot, mk, place, pointer, put, register, disposer, solid,
} = HL;

const X = 52, Y = 38, WR = 9, WT = 2.4, WH = 13, PIN = 9, PB = 5;
const REST = [-0.18, 0.22]; // the rest lean, as a share of the slider's angle

/** A run of points ordered left to right on screen. */
const LR = (pts) => (pts[0][0] <= pts[pts.length - 1][0] ? pts : pts.slice().reverse());

/** The tray's paths in the leaning camera: `far` before the floor mark, `near` after it. */
function trayPaths(P, front, outer, inner) {
  const far = [
    [poly(hull(ringAt(P, outer, 0).concat(ringAt(P, outer, WH)))), "sil"],
    [poly(ringAt(P, inner, WH)), "nf"],
    [open(ringAt(P, run(inner, (q) => !front(q)), 2.4)), "nf lo"],
  ];
  const iF = LR(ringAt(P, run(inner, front), WH));
  const oT = LR(ringAt(P, run(outer, front), WH));
  const oB = LR(ringAt(P, run(outer, front), 0));
  const near = [
    [poly([...iF, oT[oT.length - 1], ...oB.slice().reverse(), oT[0]]), "fo"],
    [open(oT), "nf lo"],
    [open(iF), "nf rim"],
    [open([oT[0], ...oB, oT[oT.length - 1]]), "nf sil"],
  ];
  return { far, near };
}

function mount({ stage, svg, read }, value) {
  const bag = disposer();
  let amp = value;
  const C = Cam(45, 0.5, 1.72);
  const reach = Math.sin(rad(14)) * X;
  fit(C, [[-X, -Y, -PIN - PB], [X, Y, -PIN - PB], [X, -Y, WH + reach], [-X, Y, WH + reach]], 200, 168);
  const P0 = proj(C), front = facing(C);

  // The plinth and the pin never move; the tray turns about the pin's head
  const g = mk("g", {}, svg);
  const [pr, pi] = rings(-X + 10, -Y + 10, X - 10, Y - 10, 8, 1.8);
  put(solid(g), prism0(P0, front, pr, pi, -PIN - PB, -PIN));
  const [nr, ni] = rings(-4, -4, 4, 4, 4, 1);
  put(solid(g), prism0(P0, front, nr, ni, -PIN, 0));

  const outer = rings(-X, -Y, X, Y, WR, WT)[0];
  const inner = rings(-X + WT, -Y + WT, X - WT, Y - WT, WR - WT, WT)[0];
  const farEls = [0, 1, 2].map(() => mk("path", {}, g));
  const mark = flatDot(g, C, 1.9, "dot");
  const nearEls = [0, 1, 2, 3].map(() => mk("path", {}, g));

  const lean = { u: spring(REST[0] * amp), v: spring(REST[1] * amp) };
  let drawn = [NaN, NaN], corner = "rest", last = null;

  /** The camera, tipped by u degrees about y and v degrees about x at the pin's head. */
  function leaning(u, v) {
    const cu = Math.cos(rad(u)), su = Math.sin(rad(u)), cv = Math.cos(rad(v)), sv = Math.sin(rad(v));
    return (x, y, z) => {
      const x1 = x * cu + z * su, z1 = -x * su + z * cu;
      return P0(x1, y * cv - z1 * sv, y * sv + z1 * cv);
    };
  }

  function draw() {
    const u = lean.u.x, v = lean.v.x;
    if (Math.abs(u - drawn[0]) < 0.01 && Math.abs(v - drawn[1]) < 0.01) return;
    drawn = [u, v];
    const P = leaning(u, v);
    const paths = trayPaths(P, front, outer, inner);
    paths.far.forEach(([d, cls], i) => { farEls[i].setAttribute("d", d); farEls[i].setAttribute("class", cls); });
    paths.near.forEach(([d, cls], i) => {
      nearEls[i].setAttribute("d", d);
      nearEls[i].setAttribute("class", cls === "nf rim" ? (corner === "rest" ? "nf" : "nf hi") : cls);
    });
    place(mark, P(X * 0.34, -Y * 0.2, 0.2));
  }

  const B = register(stage, (dt) => {
    const a = stepS(lean.u, dt), b = stepS(lean.v, dt);
    draw();
    return a || b;
  });
  bag.add(B.unregister);
  draw();

  // The pointer lands on the ground plane, which never moves, so the hit cannot flicker
  function aim(p) {
    last = p;
    if (!p) {
      corner = "rest";
      lean.u.t = REST[0] * amp;
      lean.v.t = REST[1] * amp;
    } else {
      const [wx, wy] = unproj(C, p[0], p[1], 0);
      const sx = clamp(wx / X, -1, 1), sy = clamp(wy / Y, -1, 1);
      corner = (sy < 0 ? "n" : "s") + (sx < 0 ? "w" : "e");
      lean.u.t = -sx * amp;
      lean.v.t = sy * amp;
    }
    mark.setAttribute("class", corner === "rest" ? "dot" : "dot m");
    read.textContent = corner;
    drawn = [NaN, NaN];
    B.wake();
  }
  read.textContent = "rest";
  bag.add(pointer(stage, { move: aim, leave: () => aim(null) }));
  bag.add(() => svg.replaceChildren());

  return {
    set: (val) => { amp = val; aim(last); },
    destroy: bag.dispose,
  };
}

/** A solid that does not lean: the kernel's prism, under its own name to keep the two cameras apart. */
function prism0(P, front, ring, inner, z0, z1) {
  return HL.prism(P, front, ring, inner, z0, z1);
}

hairline({
  name: "tray",
  means: "An empty tray balanced on a pin: it tips toward the pointer and settles back when the pointer leaves.",
  rules: [1, 3, 5, 8],
  range: [4, 9, 14],
  tour: [[140, 150], [262, 150], [214, 214], null],
  mount,
});
