import { initializeApp, getApps } from "https://www.gstatic.com/firebasejs/11.6.0/firebase-app.js";
import {
  getAuth,
  onAuthStateChanged,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signOut,
  updateProfile
} from "https://www.gstatic.com/firebasejs/11.6.0/firebase-auth.js";
import {
  getDatabase,
  ref,
  get,
  set,
  update,
  onValue
} from "https://www.gstatic.com/firebasejs/11.6.0/firebase-database.js";

export const ROOT_EMAIL = "ebacson@gmail.com";

export const firebaseConfig = {
  apiKey: "AIzaSyCh9CZyZEXkwqievZYXEc8dua28kj0zqbc",
  authDomain: "autocell-ebacson.firebaseapp.com",
  databaseURL: "https://autocell-ebacson-default-rtdb.firebaseio.com",
  projectId: "autocell-ebacson",
  storageBucket: "autocell-ebacson.firebasestorage.app"
};

const app = getApps().length ? getApps()[0] : initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getDatabase(app);

export function isRootEmail(email) {
  return String(email || "").trim().toLowerCase() === ROOT_EMAIL;
}

export function capsFrom(email, role) {
  const root = isRootEmail(email);
  const admin = root || !!(role && role.admin);
  const support = root || admin || !!(role && role.support);
  return {
    root,
    admin,
    support,
    canGrantAdmin: root,
    canGrantSupport: root || admin,
    canEditDevices: root || admin || support,
    label: root ? "Root" : admin ? "Admin" : support ? "Support" : "User"
  };
}

export function roleRef(uid) {
  return ref(db, "webRoles/" + uid);
}

export async function ensureWebRole(user) {
  if (!user) return null;
  const snap = await get(roleRef(user.uid));
  const email = user.email || "";
  const now = Date.now();
  if (!snap.exists()) {
    const data = {
      email,
      admin: isRootEmail(email),
      support: isRootEmail(email),
      createdAt: now,
      updatedAt: now
    };
    await set(roleRef(user.uid), data);
    return data;
  }
  const data = snap.val() || {};
  const patch = {};
  if (data.email !== email) patch.email = email;
  if (isRootEmail(email) && (!data.admin || !data.support)) {
    patch.admin = true;
    patch.support = true;
  }
  if (Object.keys(patch).length) {
    patch.updatedAt = now;
    await update(roleRef(user.uid), patch);
    return { ...data, ...patch };
  }
  return data;
}

export function watchAuth(callback) {
  return onAuthStateChanged(auth, async (user) => {
    if (!user) {
      callback(null, null, capsFrom("", null));
      return;
    }
    try {
      const role = await ensureWebRole(user);
      callback(user, role, capsFrom(user.email, role));
    } catch (err) {
      callback(user, null, capsFrom(user.email, null));
      console.warn(err);
    }
  });
}

/** Bắt buộc đăng nhập; nếu chưa có session thì chuyển về trang login. */
export function requireAuth(callback, loginPage = "auth.html") {
  return watchAuth((user, role, caps) => {
    if (!user) {
      const page = (location.pathname.split("/").pop() || "index.html") + location.search + location.hash;
      location.replace(loginPage + "?next=" + encodeURIComponent(page));
      return;
    }
    callback(user, role, caps);
  });
}

export function watchRoles(callback) {
  return onValue(ref(db, "webRoles"), (snap) => {
    const val = snap.val() || {};
    const list = Object.entries(val).map(([uid, raw]) => ({
      uid,
      email: raw?.email || "",
      admin: !!raw?.admin,
      support: !!raw?.support,
      createdAt: Number(raw?.createdAt) || 0,
      updatedAt: Number(raw?.updatedAt) || 0
    }));
    list.sort((a, b) => {
      if (isRootEmail(a.email) !== isRootEmail(b.email)) return isRootEmail(a.email) ? -1 : 1;
      if (a.admin !== b.admin) return a.admin ? -1 : 1;
      return a.email.localeCompare(b.email);
    });
    callback(list);
  }, (err) => callback([], err));
}

export async function register(email, password, displayName) {
  const cred = await createUserWithEmailAndPassword(auth, email.trim(), password);
  if (displayName && displayName.trim()) {
    await updateProfile(cred.user, { displayName: displayName.trim() });
  }
  await ensureWebRole(cred.user);
  return cred.user;
}

export async function login(email, password) {
  const cred = await signInWithEmailAndPassword(auth, email.trim(), password);
  await ensureWebRole(cred.user);
  return cred.user;
}

export async function logout(redirectTo = "auth.html") {
  await signOut(auth);
  if (redirectTo) location.replace(redirectTo);
}

export async function setWebRoleFlags(uid, patch, actorCaps) {
  if (!actorCaps) throw new Error("Chưa đăng nhập.");
  const snap = await get(roleRef(uid));
  if (!snap.exists()) throw new Error("Không thấy tài khoản web này.");
  const current = snap.val() || {};
  if (isRootEmail(current.email)) throw new Error("Không thể đổi quyền của root.");
  const next = { ...patch };
  if ("admin" in next && !actorCaps.canGrantAdmin) {
    throw new Error("Chỉ root mới được cấp/gỡ admin.");
  }
  if ("support" in next && !actorCaps.canGrantSupport) {
    throw new Error("Chỉ root hoặc admin mới được cấp/gỡ support.");
  }
  if (next.admin === true) next.support = true;
  next.updatedAt = Date.now();
  await update(roleRef(uid), next);
}

export function authErrorMessage(err) {
  const code = err && err.code ? err.code : "";
  const map = {
    "auth/email-already-in-use": "Email đã được đăng ký.",
    "auth/invalid-email": "Email không hợp lệ.",
    "auth/weak-password": "Mật khẩu tối thiểu 6 ký tự.",
    "auth/user-not-found": "Sai email hoặc mật khẩu.",
    "auth/wrong-password": "Sai email hoặc mật khẩu.",
    "auth/invalid-credential": "Sai email hoặc mật khẩu.",
    "auth/too-many-requests": "Thử quá nhiều lần. Đợi rồi thử lại.",
    "auth/network-request-failed": "Lỗi mạng. Kiểm tra kết nối."
  };
  return map[code] || (err && err.message) || "Không thực hiện được.";
}
