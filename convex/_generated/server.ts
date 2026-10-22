/**
 * HAND-WRITTEN STAND-IN for Convex codegen output. `npx convex dev` / `npx convex codegen` regenerate this
 * directory (server.js/.d.ts, api.js/.d.ts, dataModel.d.ts) and should replace this file. It exists so the
 * Convex functions typecheck against the schema without a Convex account or deployment: it binds the generic
 * builders to the DataModel derived from convex/schema.ts, which is what the generated file does.
 */
import {
  internalMutationGeneric,
  internalQueryGeneric,
  mutationGeneric,
  queryGeneric,
  type DataModelFromSchemaDefinition,
  type GenericMutationCtx,
  type GenericQueryCtx,
  type MutationBuilder,
  type QueryBuilder,
} from 'convex/server';
import type schema from '../schema';

export type DataModel = DataModelFromSchemaDefinition<typeof schema>;
export type QueryCtx = GenericQueryCtx<DataModel>;
export type MutationCtx = GenericMutationCtx<DataModel>;

export const query = queryGeneric as QueryBuilder<DataModel, 'public'>;
export const mutation = mutationGeneric as MutationBuilder<DataModel, 'public'>;
export const internalQuery = internalQueryGeneric as QueryBuilder<DataModel, 'internal'>;
export const internalMutation = internalMutationGeneric as MutationBuilder<DataModel, 'internal'>;
