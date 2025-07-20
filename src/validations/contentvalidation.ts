import { z } from "zod";

// Define the Zod enum to match the Mongoose enum
const ContentTypesEnum = z.enum([
  "document",
  "tweet",
  "youtube",
  "link",
  "image",
  "video",
  "article",
  "audio",
  "pdf",
  "docx",
  "pptx",
  "note"
]);

// Define the Zod schema
const contentSchema = z.object({
  type: ContentTypesEnum,
  link: z.string(),         // You can use .url() if you expect valid URLs
  title: z.string(),
  tags: z.array(z.string()).optional(),      // Mongoose ObjectIds are strings, so use z.string()
  userId: z.string(),             // Also an ObjectId
});

type contentSchemaTs = z.infer<typeof contentSchema>
export {contentSchema, contentSchemaTs }
