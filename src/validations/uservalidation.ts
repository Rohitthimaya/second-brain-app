import { z } from "zod";

const userSchema = z.object({
  username: z.string()
    .min(6, "Username should be at least 6 characters.")
    .max(50, "Username should not exceed 50 characters."),

  password: z.string()
    .min(8, "Password should be at least 8 characters.")
    .max(30, "Password should not exceed 30 characters.")
    .refine((val) => /[A-Z]/.test(val), {
      message: "Password must include at least one uppercase letter.",
    })
    .refine((val) => /[a-z]/.test(val), {
      message: "Password must include at least one lowercase letter.",
    })
    .refine((val) => /[0-9]/.test(val), {
      message: "Password must include at least one number.",
    })
    .refine((val) => /[^A-Za-z0-9]/.test(val), {
      message: "Password must include at least one special character.",
    }),
});

type userSchemaTs = z.infer<typeof userSchema>;

export {userSchema, userSchemaTs}
